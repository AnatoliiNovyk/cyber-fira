// js/main.js
// Головний скрипт для ініціалізації frontend логіки CYBER DASHBOARD

/**
 * Головна функція ініціалізації, яка викликається після повного завантаження DOM.
 */
function main() {
    console.log("DOM завантажено. Ініціалізація CYBER DASHBOARD Frontend v3.8.GUI-Refactored...");

    // 1. Ініціалізація навігації по вкладках
    if (typeof initializeTabs === 'function') {
        initializeTabs();
    } else {
        console.error("Функція initializeTabs не знайдена. Переконайтеся, що js/tabs_navigation.js завантажено.");
    }

    // 2. Ініціалізація обробників подій для кожної вкладки
    // Ці функції визначені у відповідних файлах *_ui.js
    if (typeof initializePayloadGeneratorEvents === 'function') {
        initializePayloadGeneratorEvents();
    } else {
        console.error("initializePayloadGeneratorEvents не знайдена (payload_generator_ui.js).");
    }
    if (typeof initializeReconnaissanceEvents === 'function') {
        initializeReconnaissanceEvents();
    } else {
        console.error("initializeReconnaissanceEvents не знайдена (reconnaissance_ui.js).");
    }
    if (typeof initializeC2ControlEvents === 'function') {
        initializeC2ControlEvents();
    } else {
        console.error("initializeC2ControlEvents не знайдена (c2_control_ui.js).");
    }
    if (typeof initializeLoggingAdaptationEvents === 'function') {
        initializeLoggingAdaptationEvents();
    } else {
        console.error("initializeLoggingAdaptationEvents не знайдена (logging_adaptation_ui.js).");
    }

    // 3. Визначення початково активної вкладки та завантаження для неї даних
    const initiallyActiveButton = document.querySelector('.tab-button.active');
    if (initiallyActiveButton) {
        const activeTabId = initiallyActiveButton.dataset.tab;
        console.log(`Початково активна вкладка: ${activeTabId}`);

        // Завантаження даних для початково активної вкладки
        if (activeTabId === 'payloadGeneratorTab') {
            if (typeof fetchPayloadArchetypes === 'function') {
                fetchPayloadArchetypes(); // Завантажуємо список архетипів
            } else {
                console.warn("fetchPayloadArchetypes не знайдена. Список архетипів не буде завантажено.");
            }
        } else if (activeTabId === 'reconnaissanceTab') {
            if (typeof fetchReconTypes === 'function') {
                fetchReconTypes(); // Завантажуємо список типів розвідки
            } else {
                console.warn("fetchReconTypes не знайдена. Список типів розвідки не буде завантажено.");
            }
        } else if (activeTabId === 'c2ControlTab') {
            if (typeof fetchAndRenderImplants === 'function') {
                fetchAndRenderImplants(); // Завантажуємо список імплантів
            } else {
                console.warn("fetchAndRenderImplants не знайдена. Список імплантів не буде завантажено.");
            }
        } else if (activeTabId === 'loggingAdaptationTab') {
            if (typeof fetchOperationalData === 'function') {
                fetchOperationalData(); // Завантажуємо оперативні дані
            } else {
                console.warn("fetchOperationalData не знайдена. Оперативні дані не будуть завантажені.");
            }
        }
    } else {
        console.warn("Не знайдено початково активної вкладки для завантаження даних.");
        // Якщо активної вкладки немає, можна спробувати активувати першу за замовчуванням
        const firstTabButton = document.querySelector('.tab-button');
        if (firstTabButton) {
            console.log("Активуємо першу вкладку за замовчуванням.");
            firstTabButton.click(); // Симулюємо клік, щоб спрацювала логіка в initializeTabs та тут
        }
    }
    
    // 4. Додаткова логіка, яка може знадобитися після ініціалізації всіх компонентів
    // Наприклад, оновлення стану GUI на основі даних з localStorage, якщо використовується.

    console.log("Основна ініціалізація Frontend завершена.");
}

// Запуск головної функції ініціалізації після завантаження DOM
document.addEventListener('DOMContentLoaded', main);
