package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

const (
	validPassword   = "testpassword"
	invalidPassword = "wrongpassword"
)

// Генерация хеша пароля
func GenerateHash(password string, cost int) (string, error) {
	pHash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(pHash), nil
}

// Общая функция проверки хешей
func checkHash(t *testing.T, hash string, password string, expectError bool) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if expectError {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

// Тестирование генерации и проверки хеша
func TestGenerateAndValidateHash(t *testing.T) {
	hash, err := GenerateHash(validPassword, 10)
	assert.NoError(t, err)

	// Проверяем валидный и невалидный пароль
	checkHash(t, hash, validPassword, false)
	checkHash(t, hash, invalidPassword, true)
}

// Тестирование генерации хеша с различной стоимостью
func TestGenerateHashWithDifferentCosts(t *testing.T) {
	costs := []int{4, 6, 8, 10, 12}
	for _, cost := range costs {
		hash, err := GenerateHash(validPassword, cost)
		assert.NoError(t, err)

		costValue, err := bcrypt.Cost([]byte(hash))
		assert.NoError(t, err)
		assert.Equal(t, cost, costValue)
	}
}

// Тестирование получения стоимости хеша
func TestGetHashCost(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(validPassword), 10)
	assert.NoError(t, err)

	// Получаем стоимость хеша
	cost, err := bcrypt.Cost([]byte(hash))
	assert.NoError(t, err)
	assert.Equal(t, 10, cost)
}
