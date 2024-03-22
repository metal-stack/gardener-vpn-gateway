package main

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"path"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

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
	logger        *slog.Logger
	stop          context.Context
	targetService *corev1.Service
	secretCronID  cron.EntryID
	serviceCronID cron.EntryID
	clusterProxy  *proxy.Proxy
)

// CronLogger is used for logging within the cron function.
type CronLogger struct {
	l *slog.Logger
}

// Info logs info messages from the cron function.
func (c *CronLogger) Info(msg string, keysAndValues ...interface{}) {
	c.l.Info(msg, keysAndValues...)
}

func (c *CronLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	c.l.Error(msg, keysAndValues...)
}

// Opts is required in order to have proper validation for args from cobra and viper.
// this is because MarkFlagRequired from cobra does not work well with viper, see:
// https://github.com/spf13/viper/issues/397
type Opts struct {
	ShootKubeconfig        string `validate:"required"`
	SeedKubeconfig         string
	SeedNamespace          string `validate:"required"`
	Namespace              string `validate:"required"`
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
	cmd.Flags().String("seed-namespace", "", "the namespace in the seed cluster in which the proxy certificates reside")
	cmd.Flags().String("namespace", "", "the namespace of the target service")
	cmd.Flags().String("service-name", "", "the service name of the target service")
	cmd.Flags().String("check-schedule", "*/1 * * * *", "cron schedule when to check for service changes")
	cmd.Flags().Duration("backoff-timer", time.Duration(10*time.Second), "Backoff time for restarting the forwarder process when it has been killed by external influences")
	cmd.Flags().String("log-level", "info", "sets the application log level")
	cmd.Flags().String("proxy-host", "vpn-seed-server", "Name of the mTLS proxy to connect to the shoot through the VPN. Expected method is http-connect.")
	cmd.Flags().String("proxy-port", "9443", "Port of the mTLS proxy specified with proxy-host.")
	cmd.Flags().String("proxy-ca-secret", "ca-vpn-bundle", "Name of the secret that contains the CA certificate use for the proxy server certificate.")
	cmd.Flags().String("proxy-client-secret", "kube-apiserver-http-proxy", "Name of the secret that contains the client certificate needed for connecting to the proxy.")
	cmd.Flags().String("tls-base-dir", "/proxy/tls", "the path to the CA file for checking the mTLS proxy server certificate")
	cmd.Flags().String("proxy-ca-file", "bundle.crt", "the path to the CA file for checking the mTLS proxy server certificate")
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
		SeedNamespace:          viper.GetString("seed-namespace"),
		Namespace:              viper.GetString("namespace"),
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
			logger.Error("Config file path set explicitly, but unreadable", "error", err)
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
				logger.Error("Config file unreadable", "config-file", usedCfg, "error", err)
				os.Exit(1)
			}
		}
	}

	usedCfg := viper.ConfigFileUsed()
	if usedCfg != "" {
		logger.Info("Read config file", "config-file", usedCfg)
	}
}

func initLogging(opts *Opts) {
	var lvlvar slog.LevelVar

	err := lvlvar.UnmarshalText([]byte(opts.LogLevel))
	if err != nil {
		log.Fatalf("can't initialize logger: %v", err)
	}
	lvlvar.Level()

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvlvar.Level()}))
}

func initSignalHandlers() {
	stop = signals.SetupSignalHandler()
}

func run(opts *Opts) error {
	logger.Debug("Options", "opts", opts)
	// Prepare K8s
	shootClient, err := loadClient(opts.ShootKubeconfig)
	if err != nil {
		logger.Error("Unable to connect to shoot k8s", "Error", err)
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
		logger.Error("Unable to connect to seed k8s", "Kubeconfig", opts.SeedKubeconfig, "Error", err)
		return err
	}

	// Set up (and run) service checker cron job
	cronjob := cron.New(cron.WithChain(
		cron.SkipIfStillRunning(&CronLogger{l: logger.WithGroup("cron")}),
	))

	secretCronID, err = cronjob.AddFunc(opts.CheckSchedule, func() {
		err := readSecrets(opts, seedClient)
		if err != nil {
			logger.Error("error during secret check", "error", err)
		}

		logger.Debug("scheduling next secret check", "at", cronjob.Entry(secretCronID).Next)
	})
	if err != nil {
		return fmt.Errorf("could not initialize cron schedule %w", err)
	}
	serviceCronID, err = cronjob.AddFunc(opts.CheckSchedule, func() {
		err := checkService(opts, shootClient)
		if err != nil {
			logger.Error("error during service check", "error", err)
		}

		logger.Debug("scheduling next service check", "at", cronjob.Entry(serviceCronID).Next)
	})
	if err != nil {
		return fmt.Errorf("could not initialize cron schedule %w", err)
	}

	logger.Info("start initial checks", "version", v.V.String())

	err = readSecrets(opts, seedClient)
	if err != nil {
		logger.Error("error during initial secret check", "error", err)
		return err
	}
	err = checkService(opts, shootClient)
	if err != nil {
		logger.Error("error during initial service check", "error", err)
		return err
	}
	cronjob.Start()
	logger.Info("cronjob interval", "check-schedule", opts.CheckSchedule)
	logger.Debug("Cronjob", "entries:", cronjob.Entries())

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
	logger.Debug("Checking service")
	// logger.Debug("Current service", "targetService", targetService)

	kubectx, cancel := context.WithTimeout(context.Background(), time.Duration(10*time.Second))
	defer cancel()
	service, err := client.CoreV1().Services(opts.Namespace).Get(kubectx, opts.ServiceName, metav1.GetOptions{})
	if err != nil { // That means no matching service found
		if targetService != nil { // This means a service was previously seen, and the proxy should already be running.
			logger.Info("Service went away, stopping proxy")
			if clusterProxy != nil { // This means there should be a running proxy, we need to stop it too.
				clusterProxy.DestroyProxy()
				clusterProxy = nil
			}
			targetService = nil
		}
		return err
	}

	// logger.Debug("Service gotten", "service", service)
	serviceIP := service.Spec.ClusterIP
	if len(service.Spec.Ports) != 1 {
		logger.Error("Service must have exactly one port", "Ports", service.Spec.Ports)
		return errors.New("service must have exactly one port")
	}
	servicePort := strconv.Itoa(int(service.Spec.Ports[0].Port))

	if targetService != nil { // This means a service was previously seen, and the proxy should already be running.
		if targetService.Spec.ClusterIP == service.Spec.ClusterIP && targetService.Spec.Ports[0].Port == service.Spec.Ports[0].Port {
			logger.Debug("Service stayed the same, nothing to do.")
			return nil
		}
		if clusterProxy != nil { // This means there should be a running proxy, we need to stop it too.
			clusterProxy.DestroyProxy()
			clusterProxy = nil
		}
	}

	logger.Info("Target identified", "IP", serviceIP, "Port", servicePort)

	if opts.ProxyHost != "" { // This means we need to start a mTLS proxy
		logger.Info("Starting proxy", "host", opts.ProxyHost, "port", opts.ProxyPort)
		clusterProxy, err = proxy.NewProxyMTLS(logger, opts.ProxyHost, opts.ProxyPort, opts.ProxyClientCrtFilename, opts.ProxyClientKeyFilename, opts.ProxyCaFilename, serviceIP, servicePort, proxyListenAddress, proxyListenPort)
		if err != nil {
			logger.Error("Could not start mTLS proxy", "error", err)
			return err
		}
	}

	targetService = service
	return nil
}

func readSecrets(opts *Opts, client *k8s.Clientset) error {
	logger.Debug("Reading secrets")
	keys := []string{opts.ProxyCaFilename, opts.ProxyClientCrtFilename, opts.ProxyClientKeyFilename}

	for _, secretName := range []string{opts.ProxyCASecret, opts.ProxyClientSecret} {
		kubectx, kubecancel := context.WithTimeout(context.Background(), time.Duration(10*time.Second))
		defer kubecancel()

		secret, err := getLatestSecret(kubectx, client, opts.SeedNamespace, secretName)
		if err != nil {
			return fmt.Errorf("did not find secret %q in namespace %s: %w", secretName, opts.SeedNamespace, err)
		}
		logger.Debug("Got secret", secretName, secret.Name)

		// Now we attempt to write the certificates to file
		for key, value := range secret.Data {
			for _, k := range keys {
				if key == k {
					f := path.Join(opts.TLSBaseDir, key)
					logger.Debug("Writing certificate to file", key, f)
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

func getLatestSecret(ctx context.Context, c *k8s.Clientset, namespace string, name string) (*corev1.Secret, error) {
	selector := labels.SelectorFromSet(map[string]string{
		"managed-by":       "secrets-manager",
		"manager-identity": "gardenlet",
		"name":             name,
	})

	secretList, err := c.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, err
	}

	return getLatestIssuedSecret(secretList.Items)
}

// getLatestIssuedSecret returns the secret with the "issued-at-time" label that represents the latest point in time
func getLatestIssuedSecret(secrets []corev1.Secret) (*corev1.Secret, error) {
	const (
		labelKeyIssuedAtTime = "issued-at-time"
	)

	if len(secrets) == 0 {
		return nil, fmt.Errorf("no secret found")
	}

	var newestSecret *corev1.Secret
	var currentIssuedAtTime time.Time
	for i := range len(secrets) {
		// if some of the secrets have no "issued-at-time" label
		// we have a problem since this is the source of truth
		issuedAt, ok := secrets[i].Labels[labelKeyIssuedAtTime]
		if !ok {
			// there are some old secrets from ancient gardener versions which have to be skipped... (e.g. ssh-keypair.old)
			continue
		}

		issuedAtUnix, err := strconv.ParseInt(issuedAt, 10, 64)
		if err != nil {
			return nil, err
		}

		issuedAtTime := time.Unix(issuedAtUnix, 0).UTC()
		if newestSecret == nil || issuedAtTime.After(currentIssuedAtTime) {
			newestSecret = &secrets[i]
			currentIssuedAtTime = issuedAtTime
		}
	}

	if newestSecret == nil {
		return nil, fmt.Errorf("no secret found")
	}

	return newestSecret, nil
}
