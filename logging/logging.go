package logging

import (
	"fmt"
	"time"
)

func LogRequest(rMethod string, rURL string, status int) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("%s %s %s %d\n", timestamp, rMethod, rURL, status)
}
