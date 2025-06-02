// js/tabs_navigation.js
// Логіка для перемикання вкладок (табів) у користувацькому інтерфейсі

/**
 * Ініціалізує функціональність перемикання вкладок.
 * Знаходить усі кнопки вкладок та відповідний вміст,
 * додає обробники подій для перемикання.
 */
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    if (tabButtons.length === 0 || tabContents.length === 0) {
        console.warn("Елементи для навігації по вкладках (кнопки або вміст) не знайдено.");
        return;
    }

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // 1. Деактивувати всі кнопки та вміст
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // 2. Активувати натиснуту кнопку
            button.classList.add('active');

            // 3. Активувати відповідний вміст
            const activeTabContentId = button.dataset.tab; // Отримуємо ID вкладки з data-tab атрибута
            const activeTabContent = document.getElementById(activeTabContentId);
            
            if (activeTabContent) {
                activeTabContent.classList.add('active');
                console.log(`Активовано вкладку: ${activeTabContentId}`);

                // Специфічні дії при активації певних вкладок
                // (наприклад, завантаження даних для C2 або логів)
                // Ці виклики будуть додані або модифіковані в main.js або відповідних UI модулях,
                // щоб уникнути прямої залежності tabs_navigation.js від конкретних функцій завантаження даних.
                // Наприклад, можна викликати кастомну подію, на яку підпишуться інші модулі.
                
                // Приклад: Якщо активували вкладку C2, викликаємо оновлення імплантів
                // (Ця логіка краще буде в main.js або c2_control_ui.js, слухаючи зміну вкладки)
                // if (activeTabContentId === 'c2ControlTab' && typeof fetchAndRenderImplants === 'function') {
                //     fetchAndRenderImplants(); 
                // } else if (activeTabContentId === 'loggingAdaptationTab' && typeof fetchOperationalData === 'function') {
                //     fetchOperationalData();
                // }

            } else {
                console.error(`Вміст для вкладки з ID '${activeTabContentId}' не знайдено.`);
            }
        });
    });

    // Перевірка, чи є активна вкладка за замовчуванням, і чи потрібно викликати для неї дії
    const initiallyActiveButton = document.querySelector('.tab-button.active');
    if (initiallyActiveButton) {
        const activeTabId = initiallyActiveButton.dataset.tab;
        const activeContent = document.getElementById(activeTabId);
        if (activeContent && !activeContent.classList.contains('active')) {
            // Це може статися, якщо JS завантажується до того, як CSS повністю застосував .active
            // Або якщо логіка активації за замовчуванням не спрацювала
            console.log(`Примусова активація початкової вкладки: ${activeTabId}`);
            activeContent.classList.add('active');
        }
        // Початкове завантаження даних для активної вкладки буде оброблятися в main.js
    }
}

// Ініціалізація вкладок після завантаження DOM.
// Це можна перенести в main.js для централізованої ініціалізації.
// document.addEventListener('DOMContentLoaded', initializeTabs);
