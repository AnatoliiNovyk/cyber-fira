// js/api.js
// Конфігурація для взаємодії з Backend API

/**
 * Базова URL-адреса для всіх API-запитів до backend.
 * Переконайтеся, що вона відповідає адресі, на якій запущено ваш Flask-сервер.
 */
const API_BASE_URL = 'http://localhost:5000/api';

// В майбутньому тут можна додати допоміжні функції для fetch,
// наприклад, для автоматичного додавання заголовків, обробки помилок тощо.
// async function fetchData(endpoint, options = {}) {
//     const url = `${API_BASE_URL}${endpoint}`;
//     try {
//         const response = await fetch(url, {
//             headers: {
//                 'Content-Type': 'application/json',
//                 ...options.headers,
//             },
//             ...options,
//         });
//         if (!response.ok) {
//             // Спробувати отримати текст помилки з відповіді, якщо є
//             let errorData;
//             try {
//                 errorData = await response.json();
//             } catch (e) {
//                 errorData = { error: `HTTP error! status: ${response.status}` };
//             }
//             console.error(`API Error (${url}):`, errorData);
//             throw errorData; // Викидаємо об'єкт помилки
//         }
//         return await response.json();
//     } catch (error) {
//         console.error(`Fetch Error (${url}):`, error);
//         throw error; // Перекидаємо помилку далі
//     }
// }
