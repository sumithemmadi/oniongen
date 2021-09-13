package main

import (
    "fmt"
    "time"
    "math/rand"
)

//var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var letters = []rune("abcdefghijklmnopqrstuvwxyz")

func RandomVariable(n int) string {
    b := make([]rune, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}

func main() {
    rand.Seed(time.Now().UnixNano())

    fmt.Println(RandomVariable(4))
}
