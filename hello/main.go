package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Printf("Hello, world\r\n")

	for t := range time.Tick(5 * time.Second) {
		fmt.Printf("The current time is %s\r\n", t)
	}
}
