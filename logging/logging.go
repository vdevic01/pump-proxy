package logging

import "log"

func LogRequest(rMethod string, rURL string, status int) {
	log.Printf("INFO: %s %s %d", rMethod, rURL, status)
}

func LogInfo(message string) {
	log.Printf("INFO: %s", message)
}

func LogError(err error) {
	log.Printf("ERROR: %v", err)
}
