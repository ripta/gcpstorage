package multisign

import (
	"context"

	"cloud.google.com/go/compute/metadata"
	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/storage"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	credentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1"
)

type CredentialType string

var (
	CredentialTypeServiceAccountKey CredentialType = "SERVICE_ACCOUNT_KEY"
	CredentialTypeWorkloadIdentity  CredentialType = "WORKLOAD_IDENTITY"
)

var (
	ErrNoAccountID           = errors.New("could not retrieve account ID from oauth2 token")
	ErrInvalidCredentialType = errors.New("invalid multisign credential type")
)

type Client struct {
	Type           CredentialType
	GoogleAccessID string
	PrivateKey     []byte
}

func New(ctx context.Context, cred *google.Credentials) (*Client, error) {
	if len(cred.JSON) > 0 {
		jwt, err := google.JWTConfigFromJSON(cred.JSON)
		if err != nil {
			return nil, errors.Wrap(err, "JWT from JSON")
		}

		return &Client{
			Type:           CredentialTypeServiceAccountKey,
			GoogleAccessID: jwt.Email,
			PrivateKey:     jwt.PrivateKey,
		}, nil
	}

	token, err := cred.TokenSource.Token()
	if err != nil {
		return nil, errors.Wrap(err, "retrieving credential token from source")
	}

	acct, ok := token.Extra("oauth2.google.serviceAccount").(string)
	if !ok {
		return nil, ErrNoAccountID
	}

	hc := oauth2.NewClient(ctx, cred.TokenSource)
	mdc := metadata.NewClient(hc)
	email, err := mdc.Email(acct)
	if err != nil {
		return nil, errors.Wrap(err, "retrieving account from metadata source")
	}

	return &Client{
		Type:           CredentialTypeWorkloadIdentity,
		GoogleAccessID: email,
	}, nil
}

func (c *Client) SignedURL(ctx context.Context, bucket, path string, opts storage.SignedURLOptions) (string, error) {
	switch c.Type {
	case CredentialTypeWorkloadIdentity:
		opts.GoogleAccessID = c.GoogleAccessID
		opts.SignBytes = func(p []byte) ([]byte, error) {
			icc, err := credentials.NewIamCredentialsClient(ctx)
			if err != nil {
				return nil, errors.Wrap(err, "creating new IAM credential client")
			}

			req := credentialspb.SignBlobRequest{
				Name:    c.GoogleAccessID,
				Payload: p,
			}

			res, err := icc.SignBlob(ctx, &req)
			if err != nil {
				return nil, errors.Wrap(err, "signing payload blob")
			}

			return res.SignedBlob, nil
		}
		return storage.SignedURL(bucket, path, &opts)

	case CredentialTypeServiceAccountKey:
		opts.GoogleAccessID = c.GoogleAccessID
		opts.PrivateKey = c.PrivateKey
		return storage.SignedURL(bucket, path, &opts)

	default:
		// no-op
	}
	return "", ErrInvalidCredentialType
}
