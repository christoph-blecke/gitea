// Copyright 2020 christoph2@shoogee.com
// Christoph Blecke | Shoogee GmbH & Co. KG

package radius

import (
	"context"
	"errors"
	"time"
	
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

//__________    _____  ________  .___ ____ ___  _________
//\______   \  /  _  \ \______ \ |   |    |   \/   _____/
// |       _/ /  /_\  \ |    |  \|   |    |   /\_____  \
// |    |   \/    |    \|    `   \   |    |  / /        \
// |____|_  /\____|__  /_______  /___|______/ /_______  /
//        \/         \/        \/                     \/

func Auth(ipAddress, port, sharedSecret, userName, passwd string, seconds int64) (string, error) {
	radiusServer := ipAddress + ":" + port

	// Define context with timeout
	timeout := time.Second * time.Duration(seconds)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() 

	// Define package
	packet := radius.New(radius.CodeAccessRequest, []byte(sharedSecret))
	rfc2865.UserName_SetString(packet, userName)
	rfc2865.UserPassword_SetString(packet, passwd)

	response, err := radius.Exchange(ctx, packet, radiusServer)
	if err != nil {
		return "", err
	}
	switch response.Code {
	case 2: //Access-Accept
		return userName, nil
	case 3: //Access-Reject
		return "", errors.New("Received Access-Reject")
	default:
		return "", errors.New("Received unsupported packet type")
	}
}
