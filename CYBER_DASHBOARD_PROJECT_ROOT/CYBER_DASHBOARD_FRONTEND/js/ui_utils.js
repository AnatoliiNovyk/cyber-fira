// js/ui_utils.js
// Допоміжні функції для маніпуляції UI

/**
 * Встановлює стан завантаження для кнопки.
 * @param {HTMLButtonElement} button - Елемент кнопки.
 * @param {boolean} isLoading - True, якщо потрібно показати стан завантаження.
 * @param {string} [defaultText=null] - Текст кнопки у звичайному стані. Якщо null, текст не змінюється.
 */
function setButtonLoadingState(button, isLoading, defaultText = null) {
    if (!button) return;
    const textSpan = button.querySelector('.button-text');
    const spinnerSpan = button.querySelector('.button-spinner');

    if (isLoading) {
        button.disabled = true;
        if (textSpan) textSpan.style.display = 'none';
        if (spinnerSpan) spinnerSpan.style.display = 'inline-block'; // Або 'flex' залежно від стилів
    } else {
        button.disabled = false;
        if (textSpan) {
            textSpan.style.display = 'inline';
            if (defaultText) {
                textSpan.textContent = defaultText;
            }
        }
        if (spinnerSpan) spinnerSpan.style.display = 'none';
    }
}

/**
 * Відображає повідомлення про помилку для вказаного елемента.
 * @param {string} elementId - ID HTML-елемента, де потрібно відобразити помилку.
 * @param {string} message - Текст повідомлення про помилку.
 */
function displayError(elementId, message) {
    const errorEl = document.getElementById(elementId);
    if (errorEl) {
        errorEl.textContent = message;
        errorEl.style.display = message ? 'block' : 'none'; // Показуємо або ховаємо елемент помилки
    } else {
        console.warn(`Елемент для помилок з ID '${elementId}' не знайдено.`);
    }
}

/**
 * Очищає всі повідомлення про помилки всередині вказаної форми.
 * @param {string} formId - ID HTML-форми.
 */
function clearAllErrors(formId) {
    const form = document.getElementById(formId);
    if (form) {
        form.querySelectorAll('.error-message').forEach(el => {
            el.textContent = '';
            el.style.display = 'none';
        });
    } else {
        console.warn(`Форму з ID '${formId}' не знайдено для очищення помилок.`);
    }
}

/**
 * Додає повідомлення до текстової області логу.
 * @param {string} logAreaId - ID текстової області для логування.
 * @param {string} message - Повідомлення для додавання.
 * @param {boolean} [isError=false] - Якщо true, повідомлення буде стилізовано як помилка.
 */
function logToUITextArea(logAreaId, message, isError = false) {
    const logArea = document.getElementById(logAreaId);
    if (logArea) {
        const timestamp = new Date().toLocaleTimeString();
        const prefix = `[${timestamp}] `;
        const fullMessage = prefix + message;
        
        const currentContent = logArea.textContent;
        logArea.textContent = currentContent ? `${currentContent}\n${fullMessage}` : fullMessage;
        
        // Автоматична прокрутка до низу
        logArea.scrollTop = logArea.scrollHeight;

        if (isError) {
            // Можна додати клас для стилізації помилок, якщо потрібно
            // logArea.classList.add('error-log-highlight'); 
        }
    } else {
        console.warn(`Текстова область для логування з ID '${logAreaId}' не знайдена.`);
    }
}


// Приклад використання (можна видалити або закоментувати)
// document.addEventListener('DOMContentLoaded', () => {
//     const testButton = document.createElement('button');
//     testButton.innerHTML = '<span class="button-text">Тест</span><span class="button-spinner" style="display:none;"><div class="spinner"></div> Завантаження...</span>';
//     document.body.appendChild(testButton);
//     setButtonLoadingState(testButton, true);
//     setTimeout(() => setButtonLoadingState(testButton, false, 'Тест завершено'), 2000);

//     const testErrorDiv = document.createElement('div');
//     testErrorDiv.id = 'test-error';
//     testErrorDiv.className = 'error-message';
//     document.body.appendChild(testErrorDiv);
//     displayError('test-error', 'Це тестова помилка!');
//     setTimeout(() => clearAllErrors(document.body.id || 'test-form'), 3000); // Потрібна форма для clearAllErrors
// });
