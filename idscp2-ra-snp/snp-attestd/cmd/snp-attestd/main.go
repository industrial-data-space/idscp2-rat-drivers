package main

import (
	"flag"
	"net"
	"os"

	"google.golang.org/grpc"

	lib "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd"
	log "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/logger"
	pb "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/snp_attestd_service"
)

type config struct {
	transport string
	address   string
	logLevel  string
	lib.Config
}

func getConfig() config {
	config := config{}
	commandLine := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	commandLine.StringVar(&config.transport, "transport", "tcp", "Transport protocol to use for the RPC interface")
	commandLine.StringVar(&config.address, "address", "127.0.0.1:6778", "Address for the RPC interface to listen on")
	commandLine.StringVar(&config.SevDevice, "sev-dev", "/dev/sev-guest", "Path to the SEV guest device")
	commandLine.StringVar(&config.CacheDir, "cache-dir", "/tmp/vcek-cache", "Cache location for certificate storage, etc.")
	commandLine.BoolVar(&config.VerifyOnly, "verify-only", false, "Whether to only accept verify requests")
	commandLine.StringVar(&config.logLevel, "log-level", "info", "Log level for the application (One of: off, crit, err, warn, info, debug, trace)")
	commandLine.Parse(os.Args[1:])
	return config
}

func decodeLogLevel(level string) int {
	switch level {
	case "off":
		return log.LogOff
	case "crit":
		return log.LogCrit
	case "err":
		return log.LogErr
	case "warn":
		return log.LogWarn
	case "info":
		return log.LogInfo
	case "debug":
		return log.LogDebug
	case "trace":
		return log.LogTrace
	default:
		return log.LogInfo
	}
}

func main() {
	config := getConfig()

	log.LogLevel = decodeLogLevel(config.logLevel)

	socket, err := net.Listen(config.transport, config.address)
	if err != nil {
		log.Fatal("Could not start network listener: %v", err)
	}

	server := grpc.NewServer()
	service, err := lib.NewAttestdServiceImpl(config.Config)
	if err != nil {
		log.Fatal("Error setting up the snp-attestd service: %v", err)
	}
	pb.RegisterSnpAttestdServiceServer(server, service)

	log.Info("snp-attestd is listening on %s:%s", config.transport, config.address)

	if err := server.Serve(socket); err != nil {
		log.Fatal("Error while executing the snp-attestd service: %v", err)
	}
}
