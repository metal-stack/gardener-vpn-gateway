package main

import (
	"errors"
	"fmt"
	"log"
	"path"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"context"
	"os"
	"strconv"
	"strings"

	"github.com/metal-stack/gardener-vpn-gateway/pkg/proxy"
	"github.com/metal-stack/v"

	"github.com/go-playground/validator/v10"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgFileType        = "yaml"
	moduleName         = "gardener-vpn-gateway"
	proxyListenAddress = "0.0.0.0"
	proxyListenPort    = "9876"
)

var (
	cfgFile       string
	logger        *zap.SugaredLogger
	logLevel      zapcore.Level
	stop          context.Context
	targetService *corev1.Service
	secretCronID  cron.EntryID
	serviceCronID cron.EntryID
	clusterProxy  *proxy.Proxy
)

// CronLogger is used for logging within the cron function.
type CronLogger struct {
	l *zap.SugaredLogger
}

// Info logs info messages from the cron function.
func (c *CronLogger) Info(msg string, keysAndValues ...interface{}) {
	c.l.Infow(msg, keysAndValues...)
}

func (c *CronLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	c.l.Errorw(msg, keysAndValues...)
}

// Opts is required in order to have proper validation for args from cobra and viper.
// this is because MarkFlagRequired from cobra does not work well with viper, see:
// https://github.com/spf13/viper/issues/397
type Opts struct {
	ShootKubeconfig        string `validate:"required"`
	SeedKubeconfig         string
	NameSpace              string `validate:"required"`
	ServiceName            string `validate:"required"`
	CheckSchedule          string
	BackoffTimer           time.Duration
	LogLevel               string
	ProxyHost              string
	ProxyPort              string
	ProxyCASecret          string
	ProxyClientSecret      string
	TLSBaseDir             string
	ProxyCaFilename        string
	ProxyClientCrtFilename string
	ProxyClientKeyFilename string
}

var cmd = &cobra.Command{
	Use:     moduleName,
	Short:   "A program to forward a connection transparently to a service in the cluster. It looks for a matching service, then listens for connections and tunnels the connection through the VPN to the target service.",
	Version: v.V.String(),
	Run: func(cmd *cobra.Command, args []string) {
		initConfig()
		opts, err := initOpts()
		if err != nil {
			log.Fatalf("unable to init options, error: %v", err)
		}
		initLogging(opts)
		initSignalHandlers()
		err = run(opts)
		if err != nil {
			log.Printf("run() function run returned with error: %v", err)
		}
	},
}

func init() {
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "alternative path to config file")

	cmd.Flags().String("shoot-kubeconfig", homedir+"/.kube/config", "path to the shoot kubeconfig")
	cmd.Flags().String("seed-kubeconfig", "", "path to the seed kubeconfig. Uses default path if empty.")
	cmd.Flags().String("namespace", "kube-system", "the namespace of the target service")
	cmd.Flags().String("service-name", "", "the service name of the target service")
	cmd.Flags().String("check-schedule", "*/1 * * * *", "cron schedule when to check for service changes")
	cmd.Flags().Duration("backoff-timer", time.Duration(10*time.Second), "Backoff time for restarting the forwarder process when it has been killed by external influences")
	cmd.Flags().String("log-level", "info", "sets the application log level")
	cmd.Flags().String("proxy-host", "vpn-seed-server", "Name of the mTLS proxy to connect to the shoot through the VPN. Expected method is http-connect.")
	cmd.Flags().String("proxy-port", "9443", "Port of the mTLS proxy specified with proxy-host.")
	cmd.Flags().String("proxy-ca-secret", "ca-vpn", "Name of the secret that contains the CA certificate use for the proxy server certificate.")
	cmd.Flags().String("proxy-client-secret", "http-proxy", "Name of the secret that contains the client certificate needed for connecting to the proxy.")
	cmd.Flags().String("tls-base-dir", "/proxy/tls", "the path to the CA file for checking the mTLS proxy server certificate")
	cmd.Flags().String("proxy-ca-file", "ca.crt", "the path to the CA file for checking the mTLS proxy server certificate")
	cmd.Flags().String("proxy-client-crt-file", "tls.crt", "the path to the proxy client certificate used to authenticate to the mTLS proxy server")
	cmd.Flags().String("proxy-client-key-file", "tls.key", "the path to the private key file belonging to the proy client certificate")

	err = viper.BindPFlags(cmd.Flags())
	if err != nil {
		log.Fatalf("unable to construct root command, error: %v", err)
	}
}

func initOpts() (*Opts, error) {
	opts := &Opts{
		ShootKubeconfig:        viper.GetString("shoot-kubeconfig"),
		SeedKubeconfig:         viper.GetString("seed-kubeconfig"),
		NameSpace:              viper.GetString("namespace"),
		ServiceName:            viper.GetString("service-name"),
		CheckSchedule:          viper.GetString("check-schedule"),
		BackoffTimer:           viper.GetDuration("backoff-timer"),
		LogLevel:               viper.GetString("log-level"),
		ProxyHost:              viper.GetString("proxy-host"),
		ProxyPort:              viper.GetString("proxy-port"),
		ProxyCASecret:          viper.GetString("proxy-ca-secret"),
		ProxyClientSecret:      viper.GetString("proxy-client-secret"),
		ProxyCaFilename:        viper.GetString("proxy-ca-file"),
		ProxyClientCrtFilename: viper.GetString("proxy-client-crt-file"),
		ProxyClientKeyFilename: viper.GetString("proxy-client-key-file"),
	}

	validate := validator.New()
	err := validate.Struct(opts)
	if err != nil {
		return nil, err
	}

	return opts, nil
}

func main() {
	zap, _ := zap.NewProduction()
	defer func() {
		_ = zap.Sync()
	}()
	logger = zap.Sugar()
	if err := cmd.Execute(); err != nil {
		logger.Error("Failed executing root command", "Error", err)
	}
}

func initConfig() {
	viper.SetEnvPrefix("gateway")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	viper.SetConfigType(cfgFileType)

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			logger.Errorw("Config file path set explicitly, but unreadable", "error", err)
			os.Exit(1)
		}
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("/etc/" + moduleName)
		viper.AddConfigPath("$HOME/." + moduleName)
		viper.AddConfigPath(".")
		if err := viper.ReadInConfig(); err != nil {
			usedCfg := viper.ConfigFileUsed()
			if usedCfg != "" {
				logger.Errorw("Config file unreadable", "config-file", usedCfg, "error", err)
				os.Exit(1)
			}
		}
	}

	usedCfg := viper.ConfigFileUsed()
	if usedCfg != "" {
		logger.Infow("Read config file", "config-file", usedCfg)
	}
}

func initLogging(opts *Opts) {
	err := logLevel.UnmarshalText([]byte(opts.LogLevel))
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(logLevel)

	log.Printf("Log level: %s", cfg.Level)

	l, err := cfg.Build()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	logger = l.Sugar()
}

func initSignalHandlers() {
	stop = signals.SetupSignalHandler()
}

func run(opts *Opts) error {
	logger.Debugw("Options", "opts", opts)
	// Prepare K8s
	shootClient, err := loadClient(opts.ShootKubeconfig)
	if err != nil {
		logger.Errorw("Unable to connect to shoot k8s", "Error", err)
		return err
	}

	var seedClient *k8s.Clientset
	if opts.SeedKubeconfig != "" {
		seedClient, err = loadClient(opts.SeedKubeconfig)
	} else {
		seedConfig := ctrl.GetConfigOrDie()
		seedClient, err = k8s.NewForConfig(seedConfig)
	}
	if err != nil {
		logger.Errorw("Unable to connect to seed k8s", "Kubeconfig", opts.SeedKubeconfig, "Error", err)
		return err
	}

	// Set up (and run) service checker cron job
	cronjob := cron.New(cron.WithChain(
		cron.SkipIfStillRunning(&CronLogger{l: logger.Named("cron")}),
	))

	secretCronID, err = cronjob.AddFunc(opts.CheckSchedule, func() {
		err := readSecrets(opts, seedClient)
		if err != nil {
			logger.Errorw("error during secret check", "error", err)
		}

		logger.Debugw("scheduling next secret check", "at", cronjob.Entry(secretCronID).Next)
	})
	if err != nil {
		return fmt.Errorf("could not initialize cron schedule %w", err)
	}
	serviceCronID, err = cronjob.AddFunc(opts.CheckSchedule, func() {
		err := checkService(opts, shootClient)
		if err != nil {
			logger.Errorw("error during service check", "error", err)
		}

		logger.Debugw("scheduling next service check", "at", cronjob.Entry(serviceCronID).Next)
	})
	if err != nil {
		return fmt.Errorf("could not initialize cron schedule %w", err)
	}

	logger.Infow("start initial checks", "version", v.V.String())

	err = readSecrets(opts, seedClient)
	if err != nil {
		logger.Errorw("error during initial secret check", "error", err)
	}
	err = checkService(opts, shootClient)
	if err != nil {
		logger.Errorw("error during initial service check", "error", err)
	}
	cronjob.Start()
	logger.Infow("cronjob interval", "check-schedule", opts.CheckSchedule)
	logger.Debugw("Cronjob", "entries:", cronjob.Entries())

	<-stop.Done()
	logger.Info("received stop signal, shutting down...")

	cronjob.Stop()
	return nil

}

func loadClient(kubeconfigPath string) (*k8s.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return k8s.NewForConfig(config)
}

// I think this can be implemented much easier with a Watch on the service

/*
example from client-go

	func main() {
	    config, err := clientcmd.BuildConfigFromFlags("", "")
	    if err != nil {
	        glog.Errorln(err)
	    }
	    clientset, err := kubernetes.NewForConfig(config)
	    if err != nil {
	        glog.Errorln(err)
	    }

	    kubeInformerFactory := kubeinformers.NewSharedInformerFactory(clientset, time.Second*30)
	    svcInformer := kubeInformerFactory.Core().V1().Services().Informer()

	    svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
	        AddFunc: func(obj interface{}) {
	            fmt.Printf("service added: %s \n", obj)
	        },
	        DeleteFunc: func(obj interface{}) {
	            fmt.Printf("service deleted: %s \n", obj)
	        },
	        UpdateFunc: func(oldObj, newObj interface{}) {
	            fmt.Printf("service changed: %s \n", newObj)
	        },
	    },)

	    stop := make(chan struct{})
	    defer close(stop)
	    kubeInformerFactory.Start(stop)
	    for {
	        time.Sleep(time.Second)
	    }
	}
*/
func checkService(opts *Opts, client *k8s.Clientset) error {
	logger.Debugw("Checking service")
	// logger.Debugw("Current service", "targetService", targetService)

	kubectx, cancel := context.WithTimeout(context.Background(), time.Duration(10*time.Second))
	defer cancel()
	service, err := client.CoreV1().Services(opts.NameSpace).Get(kubectx, opts.ServiceName, metav1.GetOptions{})
	if err != nil { // That means no matching service found
		if targetService != nil { // This means a service was previously seen, and the proxy should already be running.
			logger.Infow("Service went away, stopping proxy")
			if clusterProxy != nil { // This means there should be a running proxy, we need to stop it too.
				clusterProxy.DestroyProxy()
				clusterProxy = nil
			}
			targetService = nil
		}
		return err
	}

	// logger.Debugw("Service gotten", "service", service)
	serviceIP := service.Spec.ClusterIP
	if len(service.Spec.Ports) != 1 {
		logger.Errorw("Service must have exactly one port", "Ports", service.Spec.Ports)
		return errors.New("service must have exactly one port")
	}
	servicePort := strconv.Itoa(int(service.Spec.Ports[0].Port))

	if targetService != nil { // This means a service was previously seen, and the proxy should already be running.
		if targetService.Spec.ClusterIP == service.Spec.ClusterIP && targetService.Spec.Ports[0].Port == service.Spec.Ports[0].Port {
			logger.Debugw("Service stayed the same, nothing to do.")
			return nil
		}
		if clusterProxy != nil { // This means there should be a running proxy, we need to stop it too.
			clusterProxy.DestroyProxy()
			clusterProxy = nil
		}
	}

	logger.Infow("Target identified", "IP", serviceIP, "Port", servicePort)

	if opts.ProxyHost != "" { // This means we need to start a mTLS proxy
		logger.Infow("Starting proxy", "host", opts.ProxyHost, "port", opts.ProxyPort)
		clusterProxy, err = proxy.NewProxyMTLS(logger, opts.ProxyHost, opts.ProxyPort, opts.ProxyClientCrtFilename, opts.ProxyClientKeyFilename, opts.ProxyCaFilename, serviceIP, servicePort, proxyListenAddress, proxyListenPort)
		if err != nil {
			logger.Errorw("Could not start mTLS proxy", "error", err)
			return err
		}
	}

	targetService = service
	return nil
}

func readSecrets(opts *Opts, client *k8s.Clientset) error {
	logger.Debugw("Reading secrets")
	keys := []string{opts.ProxyCaFilename, opts.ProxyClientCrtFilename, opts.ProxyClientKeyFilename}

	for _, secretName := range []string{opts.ProxyCASecret, opts.ProxyClientSecret} {
		kubectx, kubecancel := context.WithTimeout(context.Background(), time.Duration(10*time.Second))
		defer kubecancel()

		secret, err := client.CoreV1().Secrets(opts.NameSpace).Get(kubectx, secretName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("did not find secret %q in namespace %s: %w", secretName, opts.NameSpace, err)
		}
		logger.Debugw("Got secret", secretName, secret.Name)

		// Now we attempt to write the certificates to file
		for key, value := range secret.Data {
			for _, k := range keys {
				if key == k {
					f := path.Join(opts.TLSBaseDir, key)
					logger.Debugw("Writing certificate to file", key, f)
					err := os.WriteFile(f, value, 0600)
					if err != nil {
						return fmt.Errorf("could not write secret to certificate base folder:%w", err)
					}
				}
			}
		}

	}

	return nil
}
