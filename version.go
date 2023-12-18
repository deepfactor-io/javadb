package main

import (
	"fmt"
	"pkg/cmd/db"
)

func main() {
	fmt.Println(db.SchemaVersion)
}
