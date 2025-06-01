// js/reconnaissance_ui.js
// UI логіка для вкладки "Розвідка"

// --- DOM Елементи ---
let reconForm, reconTargetInput, reconTypeSelect, 
    nmapOptionsContainer, nmapOptionsInput, startReconButton,
    reconOutputSection, reconResultsOutput, reconLogOutput; // Змінено reconLog на reconLogOutput для уникнення конфлікту імен

/**
 * Ініціалізує елементи DOM та обробники подій для вкладки "Розвідка".
 */
function initializeReconnaissanceEvents() {
    reconForm = document.getElementById('reconForm');
    reconTargetInput = document.getElementById('reconTarget');
    reconTypeSelect = document.getElementById('reconType');
    nmapOptionsContainer = document.getElementById('nmapOptionsContainer');
    nmapOptionsInput = document.getElementById('nmapOptionsStr');
    startReconButton = document.getElementById('startReconButton');
    reconOutputSection = document.getElementById('reconOutputSection');
    reconResultsOutput = document.getElementById('reconResultsOutput');
    reconLogOutput = document.getElementById('reconLog'); // Використовуємо нове ім'я

    if (!reconForm || !reconTargetInput || !reconTypeSelect || !startReconButton) {
        console.error("Ключові елементи форми розвідки не знайдено!");
        return;
    }

    // Показ/приховування опцій Nmap залежно від типу розвідки
    reconTypeSelect.addEventListener('change', function() {
        if (this.value.includes('nmap')) {
            if (nmapOptionsContainer) nmapOptionsContainer.classList.remove('hidden');
        } else {
            if (nmapOptionsContainer) nmapOptionsContainer.classList.add('hidden');
        }
        clearAllErrors('reconForm'); // Очищаємо помилки при зміні типу
    });
    // Ініціалізація стану видимості при завантаженні
    if (reconTypeSelect.value.includes('nmap')) {
        if (nmapOptionsContainer) nmapOptionsContainer.classList.remove('hidden');
    } else {
        if (nmapOptionsContainer) nmapOptionsContainer.classList.add('hidden');
    }

    // Обробник відправки форми розвідки
    reconForm.addEventListener('submit', handleReconFormSubmit);
}

/**
 * Валідує форму розвідки на стороні клієнта.
 * @returns {boolean} - True, якщо форма валідна, інакше false.
 */
function validateReconFormClientSide() {
    clearAllErrors('reconForm'); // Використовуємо ui_utils.js
    let isValid = true;
    const target = reconTargetInput.value.trim();

    if (!target) {
        displayError('error-reconTarget', "Ціль для розвідки є обов'язковою.");
        isValid = false;
    } else if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?:[\/\w \.-]*)*$/.test(target)) {
        // Дозволено також шляхи для деяких типів сканувань, хоча для IP/домену це основне
        // Для більш точної валідації можна перевіряти тип розвідки
        // displayError('error-reconTarget', 'Невірний формат цілі. Очікується IP, домен або URL.');
        // isValid = false; 
        // Поки що залишимо більш загальну перевірку, оскільки деякі інструменти можуть приймати URL
    }
    
    // Додаткова валідація для опцій Nmap, якщо вони видимі
    if (nmapOptionsContainer && !nmapOptionsContainer.classList.contains('hidden')) {
        const nmapOpts = nmapOptionsInput.value.trim();
        // Проста перевірка на потенційно небезпечні символи або команди, можна розширити
        if (/[;&|`$()]/.test(nmapOpts)) {
            displayError('error-nmapOptionsStr', 'Опції Nmap містять потенційно небезпечні символи.');
            isValid = false;
        }
    }

    return isValid;
}

/**
 * Обробляє відправку форми розвідки.
 * @param {Event} event - Подія відправки форми.
 */
async function handleReconFormSubmit(event) {
    event.preventDefault();
    if (!startReconButton || !reconOutputSection || !reconResultsOutput || !reconLogOutput) return;

    setButtonLoadingState(startReconButton, true, 'Запустити Розвідку');
    
    if (!validateReconFormClientSide()) {
        logToUITextArea(reconLogOutput.id, '[CLIENT_VALIDATION_FAILURE] Будь ласка, виправте помилки у формі розвідки.');
        reconOutputSection.classList.add('hidden');
        setButtonLoadingState(startReconButton, false, 'Запустити Розвідку');
        return;
    }

    const target = reconTargetInput.value.trim();
    const type = reconTypeSelect.value;
    let nmap_options_str = "";
    if (type.includes('nmap') && nmapOptionsInput) {
        nmap_options_str = nmapOptionsInput.value.trim();
    }

    logToUITextArea(reconLogOutput.id, `[GUI_INFO] Відправка запиту на розвідку (тип: '${type}', ціль: '${target}', Nmap опції: '${nmap_options_str}') на ${API_BASE_URL}/recon/run ...`);
    reconResultsOutput.textContent = 'Очікування відповіді від backend...';
    reconOutputSection.classList.remove('hidden');

    try {
        const response = await fetch(`${API_BASE_URL}/recon/run`, { // Використовуємо API_BASE_URL з api.js
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                target: target, 
                recon_type: type, 
                nmap_options_str: nmap_options_str 
            }),
        });
        const responseData = await response.json();

        reconLogOutput.textContent = ''; // Очищаємо попередній лог
        logToUITextArea(reconLogOutput.id, responseData.reconLog || "Лог розвідки не отримано від backend.");

        if (response.ok && responseData.success) {
            reconResultsOutput.textContent = responseData.reconResults || "Результати розвідки не отримано.";
        } else {
            const errorMsg = `Помилка від backend: ${responseData.error || response.statusText || 'Невідома помилка'}`;
            reconResultsOutput.textContent = errorMsg;
            logToUITextArea(reconLogOutput.id, errorMsg, true);
        }
    } catch (error) {
        const errorMsg = `[GUI_ERROR] Помилка мережевого запиту до backend: ${error.message || error}`;
        logToUITextArea(reconLogOutput.id, errorMsg, true);
        reconResultsOutput.textContent = `Помилка зв'язку з backend. Деталі в консолі та логах GUI.`;
        console.error("Reconnaissance fetch error:", error);
    } finally {
        setButtonLoadingState(startReconButton, false, 'Запустити Розвідку');
    }
}


/**
 * Завантажує список типів розвідки з backend та заповнює select.
 */
async function fetchReconTypes() {
    if (!reconTypeSelect) return;

    console.log("[ReconUI] Завантаження типів розвідки...");
    try {
        const response = await fetch(`${API_BASE_URL}/recon/types`); // Використовуємо API_BASE_URL
        const data = await response.json();

        if (data.success && data.recon_types) {
            reconTypeSelect.innerHTML = ''; // Очистити старі опції
            data.recon_types.forEach(rtype => {
                const option = document.createElement('option');
                option.value = rtype.id;
                option.textContent = rtype.name;
                reconTypeSelect.appendChild(option);
            });
            console.log("[ReconUI] Типи розвідки успішно завантажені.");
            // Після завантаження, ініціалізуємо видимість опцій Nmap
            if (reconTypeSelect.value) {
                reconTypeSelect.dispatchEvent(new Event('change'));
            }
        } else {
            console.error("[ReconUI] Помилка завантаження типів розвідки:", data.error || "Невідома помилка.");
            if(reconLogOutput) logToUITextArea(reconLogOutput.id, `Помилка завантаження типів розвідки: ${data.error || "Невідома помилка."}`, true);
        }
    } catch (error) {
        console.error("[ReconUI] Мережева помилка при завантаженні типів розвідки:", error);
         if(reconLogOutput) logToUITextArea(reconLogOutput.id, `Мережева помилка при завантаженні типів розвідки: ${error.message}`, true);
    }
}


// Ініціалізація при завантаженні скрипта (буде викликана з main.js)
// initializeReconnaissanceEvents();
// fetchReconTypes(); 
