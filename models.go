package main

type User struct {
	ID        uint64
	Name      string
	Password  string
	Email     string
	Role      string
	CreatedAt int64
}

type Entry struct {
	ID        uint64
	Hash      []byte
	Data      []byte
	Filename  string
	UserId    uint64
	URL       string
	CreatedAt int64
}

type Session struct {
	SessionHash []byte
	UserId      uint64
	CreatedAt   int64
}
