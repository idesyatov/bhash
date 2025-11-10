package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// Генерация хеша пароля
func GenerateHash(password string, cost int) (string, error) {
	pHash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(pHash), nil
}

// Тестирование генерации хеша
func TestGenerateHash(t *testing.T) {
	hash, err := GenerateHash("testpassword", 10)
	assert.NoError(t, err)

	// Проверка валидности хеша
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("testpassword"))
	assert.NoError(t, err)
}

// Тестирование проверки пароля с использованием сгенерированного хеша
func TestValidateHash(t *testing.T) {
	hash, err := GenerateHash("testpassword", 10)
	assert.NoError(t, err)

	// Проверяем, что хеш соответствует паролю
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("testpassword"))
	assert.NoError(t, err)

	// Проверяем неверный пароль
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrongpassword"))
	assert.Error(t, err)
}

// Тестирование получения стоимости хеша
func TestGetHashCost(t *testing.T) {
	// Генерируем тестовый хеш
	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), 10)
	assert.NoError(t, err)

	// Получаем стоимость хеша
	cost, err := bcrypt.Cost(hash)
	assert.NoError(t, err)
	assert.Equal(t, 10, cost)
}
