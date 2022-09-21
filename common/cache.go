package common

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v9"
)

var ctx = context.Background()
var rdb *redis.Client

func newRedisClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     RedisHost,
		Password: RedisPass,
		DB:       7,
	})
}

func Cache(host string, port string, user string, pass string) {
	if rdb == nil && RedisHost != "" {
		rdb = newRedisClient()
	} else if RedisHost == "" {
		return
	}

	err := rdb.Set(ctx, fmt.Sprintf("fscan:password-scan:%s-%s:%s-%s", host, port, user, pass), 1, time.Duration(RedisTtl)*time.Hour).Err()

	if err != nil {
		panic(err)
	}
}

func IsScanned(host string, port string, user string, pass string) bool {
	if rdb == nil && RedisHost != "" {
		rdb = newRedisClient()
	} else {
		return false
	}

	val, err := rdb.Exists(ctx, fmt.Sprintf("fscan:password-scan:%s-%s:%s-%s", host, port, user, pass)).Result()
	if err != nil {
		panic(err)
	}

	return val == 1
}
