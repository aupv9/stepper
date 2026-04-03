// Package goredis provides a go-redis/v9 adapter implementing token.RedisClient.
package goredis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	iamtoken "github.com/common-iam/iam/pkg/core/token"
)

// Adapter wraps a *redis.Client to satisfy the token.RedisClient interface.
type Adapter struct {
	client *redis.Client
}

// New creates a token.RedisClient backed by the given go-redis client.
func New(client *redis.Client) iamtoken.RedisClient {
	return &Adapter{client: client}
}

func (a *Adapter) Get(ctx context.Context, key string) (string, error) {
	val, err := a.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return val, err
}

func (a *Adapter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return a.client.Set(ctx, key, value, ttl).Err()
}

func (a *Adapter) Del(ctx context.Context, keys ...string) error {
	return a.client.Del(ctx, keys...).Err()
}

func (a *Adapter) FlushDB(ctx context.Context) error {
	return a.client.FlushDB(ctx).Err()
}
