package awsrds

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
)

const iso8601BasicFormat = "20060102T150405Z"

type authTokenBuilder interface {
	buildAuthToken(ctx context.Context, endpoint string, region string, dbUser string, creds aws.CredentialsProvider, optFns ...func(options *auth.BuildAuthTokenOptions)) (string, error)
}

type tokenGetter interface {
	getAuthToken(ctx context.Context, params *Config, tokenBuilder authTokenBuilder) (string, error)
}

type authToken struct {
	token     string
	expiresAt time.Time
}

func (a *authToken) getAuthToken(ctx context.Context, config *Config, tokenBuilder authTokenBuilder) (string, error) {
	if config == nil {
		return "", errors.New("missing config")
	}

	if tokenBuilder == nil {
		return "", errors.New("missing token builder")
	}

	if !a.isExpired() {
		return a.token, nil
	}

	awsClientConfig, err := newAWSClientConfig(ctx, config)
	if err != nil {
		return "", fmt.Errorf("failed to create AWS Config: %w", err)
	}

	authenticationToken, err := tokenBuilder.buildAuthToken(ctx, config.Endpoint,
		config.Region,
		config.DbUser,
		awsClientConfig.Credentials)
	if err != nil {
		return "", fmt.Errorf("failed to build authentication token: %w", err)
	}

	values, err := url.ParseQuery(authenticationToken)
	if err != nil {
		return "", fmt.Errorf("failed to parse authentication token: %w", err)
	}

	dateValues := values["X-Amz-Date"]
	if len(dateValues) != 1 {
		return "", errors.New("malformed token: could not get X-Amz-Date value")
	}

	dateTime, err := time.Parse(iso8601BasicFormat, dateValues[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse X-Amz-Date date: %w", err)
	}

	durationValues := values["X-Amz-Expires"]
	if len(durationValues) != 1 {
		return "", errors.New("malformed token: could not get X-Amz-Expires value")
	}

	// X-Amz-Expires is expressed as a duration in seconds.
	durationTime, err := time.ParseDuration(fmt.Sprintf("%ss", durationValues[0]))
	if err != nil {
		return "", fmt.Errorf("failed to parse X-Amz-Expires duration: %w", err)
	}
	a.token = authenticationToken
	a.expiresAt = dateTime.Add(durationTime)
	return authenticationToken, nil
}

func (a *authToken) isExpired() bool {
	clockSkew := time.Minute // Make sure that the authentication token is valid for one more minute.
	return nowFunc().Add(-clockSkew).Sub(a.expiresAt) >= 0
}

type awsTokenBuilder struct{}

func (a *awsTokenBuilder) buildAuthToken(ctx context.Context, endpoint string, region string, dbUser string, creds aws.CredentialsProvider, optFns ...func(options *auth.BuildAuthTokenOptions)) (string, error) {
	return auth.BuildAuthToken(ctx, endpoint, region, dbUser, creds, optFns...)
}

func newAWSClientConfig(ctx context.Context, c *Config) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(c.Region),
	)
	if err != nil {
		return aws.Config{}, err
	}

	if c.SecretAccessKey != "" && c.AccessKeyID != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, "")
	}

	return cfg, nil
}
