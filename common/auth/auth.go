package auth

import (
	"sync"

	"github.com/sagernet/sing/common"
)

type User struct {
	Username string
	Password string
}

type Authenticator struct {
	userMap map[string][]string
	mu      *sync.RWMutex
}

func NewAuthenticator(users []User) *Authenticator {
	if len(users) == 0 {
		return nil
	}
	au := &Authenticator{
		userMap: make(map[string][]string),
		mu:      &sync.RWMutex{},
	}
	for _, user := range users {
		au.userMap[user.Username] = append(au.userMap[user.Username], user.Password)
	}
	return au
}

func (au *Authenticator) Verify(username string, password string) bool {
	au.mu.RLock()
	defer au.mu.RUnlock()
	passwordList, ok := au.userMap[username]
	return ok && common.Contains(passwordList, password)
}

func (au *Authenticator) UpdateUser(user *User) {
	au.mu.Lock()
	defer au.mu.Unlock()
	au.userMap[user.Username] = []string{user.Password}
}

func (au *Authenticator) DeleteUser(username string) {
	au.mu.Lock()
	defer au.mu.Unlock()
	delete(au.userMap, username)
}
