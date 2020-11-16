// Copyright 2020: Christoph Blecke, Shoogee. All rights reserved

package models

import (
	"crypto/subtle"
	"fmt"

	"code.gitea.io/gitea/modules/timeutil"

	"golang.org/x/crypto/argon2"
)

// UserSession represents an individual and unique session ID that is assigned to a user
type UserSession struct {
	ID			 int64              `xorm:"pk autoincr"`
	UID			 int64              `xorm:"NOT NULL"`
	SessionHash	 string             `xorm:"NOT NULL"`
	PasswordHash string             `xorm:"NOT NULL"`
	Timeout		 timeutil.TimeStamp	`xorm:"NOT NULL"`
	IsActive	 bool				
}

// GetActiveUserSessions returns all active user sessions belongs to a given user
// This function also delete all expired user sessions
func GetActiveUserSessions(uid int64) ([]*UserSession, error) {
	userSessions := make([]*UserSession, 0, 4)
	if err := x.
		Where("uid=?", uid).
		Find(&userSessions); err != nil {
		return nil, err
	}

	_, err := GetUserByID(uid)
	if err != nil {
		return nil, err
	}

	activeUserSessions := make([]*UserSession, 0, 4)
	for _, userSession := range userSessions {
		if userSession.Timeout >= timeutil.TimeStampNow() {
			activeUserSessions = append(activeUserSessions, userSession)
		} else {
			// Delete not active (expired) UserSessions
			err = DeleteUserSession(userSession)
		}
	}

	return activeUserSessions, err
}

// DeleteActiveSessionsByClients deletes all sessions of the user by client
func DeleteActiveSessionsByClient (uid int64, ipAddress, client string) error {
	u, err := GetUserByID(uid)
	if err != nil {
		return err
	}

	tmpSession := hashString(ipAddress+client, u.Salt)
	userSessions := make([]*UserSession, 0, 4)
	if err := x.
		Where("session_hash=?", tmpSession).
		Find(&userSessions); err != nil {
		return err
	}

	for _, userSession := range userSessions {
		err = DeleteUserSession(userSession)
		if err != nil {
			return err
		}
	}

	return nil
}

func hashString(stringToHash, salt string) string {
	var tempSession []byte

	tempSession = argon2.IDKey([]byte(stringToHash), []byte(salt), 2, 65536, 8, 50)

	return fmt.Sprintf("%x", tempSession)
}

func createUserSession(e Engine, us *UserSession) (err error) {
	if _, err = e.Insert(us); err != nil {
		return err
	}
	
	return nil
}

// ValidateSession validates the given ip address and client against the session hash
func (us *UserSession) ValidateSession(uid int64, ipAddress, client, password string) bool {
	u, err := GetUserByID(uid)
	if err != nil {
		return false
	}

	tmpSession := hashString(ipAddress+client, u.Salt)
	tmpPasswd := hashString(password, u.Salt)

	checkClient := subtle.ConstantTimeCompare([]byte(us.SessionHash), []byte(tmpSession)) == 1
	checkPasswd := subtle.ConstantTimeCompare([]byte(us.PasswordHash), []byte(tmpPasswd)) == 1
	isActive := us.IsActive && (us.Timeout > timeutil.TimeStampNow())
	if checkClient && checkPasswd && isActive {
		return true
	} 
	return false
}

// CreateUserSession creates a new session from the client and the IP
func CreateUserSession(uid int64, ipAddress, client, password string, seconds int64) (err error) {
	u, err := GetUserByID(uid)
	if err != nil {
		return err
	}

	// Calculate a hash from the client, ip address and the user salt
	tmpSession := hashString(ipAddress+client, u.Salt)
	tmpPasswd := hashString(password, u.Salt)
	timeout := timeutil.TimeStampNow().Add(seconds)

	userSession := UserSession{
		UID: 			uid,
		SessionHash:	tmpSession,
		PasswordHash:   tmpPasswd,
		Timeout: 		timeout,
		IsActive: 		true,
	}

	return createUserSession(x, &userSession)
}

// DeleteUserSession deletes a session from the database
func DeleteUserSession(us *UserSession) (err error) {
	var deleted int64

	if us.ID > 0 {
		deleted, err = x.ID(us.ID).Delete(us)
	} else {
		deleted, err = x.
			Where("sessionhash=?", us.SessionHash).
			Delete(&us)			
	}

	if err != nil {
		return err
	} else if deleted != 1 {
		return ErrUserSessionNotExist{us.UID}
	}
	return nil
}