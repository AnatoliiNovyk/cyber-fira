// js/payload_generator_ui.js
// UI логіка для вкладки "Генератор Пейлоадів"

// --- DOM Елементи ---
let payloadForm, payloadArchetypeSelect, archetypeParamsContainer,
    payloadOutputSection, payloadStagerOutput, payloadGenerationLog,
    generatePayloadButton, outputFormatSelect, pyinstallerOptionsContainer,
    enableStagerDebugPrintsCheckbox;

// --- Стан ---
let payloadArchetypesLoaded = false; // Прапорець для відстеження завантаження архетипів

// --- Конфігурація секцій параметрів (можна розширити або завантажувати) ---
const payloadParamSectionsConfigFE = {
    "demo_echo_payload": { sectionId: 'params_demo_echo_payload', fields: ['messageToEcho'] },
    "demo_file_lister_payload": { sectionId: 'params_demo_file_lister_payload', fields: ['directoryToList'] },
    "demo_c2_beacon_payload": { sectionId: 'params_demo_c2_beacon_payload', fields: ['c2BeaconEndpoint'] },
    "reverse_shell_tcp_shellcode_windows_x64": { sectionId: 'params_reverse_shell_tcp', fields: ['c2TargetHostShell', 'c2TargetPortShell', 'shellcodeHexPlaceholder'] },
    "reverse_shell_tcp_shellcode_linux_x64": { sectionId: 'params_reverse_shell_tcp', fields: ['c2TargetHostShell', 'c2TargetPortShell', 'shellcodeHexPlaceholder'] },
    "powershell_downloader_stager": { sectionId: 'params_powershell_downloader_stager', fields: ['powershellScriptUrl', 'powershellExecutionArgs'] },
    "dns_beacon_c2_concept": { sectionId: 'params_dns_beacon_c2_concept', fields: ['c2DnsZone', 'dnsBeaconSubdomainPrefix'] },
    "windows_simple_persistence_stager": { sectionId: 'params_windows_simple_persistence_stager', fields: ['persistenceMethod', 'commandToPersist', 'artifactName'] }
};

// --- Правила валідації на стороні клієнта (доповнення до серверної) ---
const payloadValidationRulesFE = {
    "payload_archetype": { required: true, message: "Архетип пейлоада є обов'язковим." },
    "messageToEcho": { 
        requiredIf: "demo_echo_payload", 
        minLength: 1, 
        messageRequired: "Повідомлення для ехо є обов'язковим.",
        messageMinLength: "Повідомлення має містити хоча б 1 символ."
    },
    "c2BeaconEndpoint": { 
        requiredIf: "demo_c2_beacon_payload", 
        isUrl: true,
        messageRequired: "URL ендпоінта C2 є обов'язковим.",
        messageUrl: "Невірний формат URL для ендпоінта C2."
    },
    "c2TargetHostShell": {
        requiredIf: ["reverse_shell_tcp_shellcode_windows_x64", "reverse_shell_tcp_shellcode_linux_x64"],
        isHostOrIp: true,
        messageRequired: "Хост C2 (LHOST) є обов'язковим.",
        messageHostOrIp: "Невірний формат хоста або IP-адреси для LHOST."
    },
    "c2TargetPortShell": {
        requiredIf: ["reverse_shell_tcp_shellcode_windows_x64", "reverse_shell_tcp_shellcode_linux_x64"],
        isPort: true,
        messageRequired: "Порт C2 (LPORT) є обов'язковим.",
        messagePort: "Порт має бути числом від 1 до 65535."
    },
    "shellcodeHexPlaceholder": {
        requiredIf: ["reverse_shell_tcp_shellcode_windows_x64", "reverse_shell_tcp_shellcode_linux_x64"],
        isHex: true, // Дозволимо порожній, якщо DEADBEEFCAFE використовується як реальний плейсхолдер
        messageRequired: "Шеллкод (HEX) є обов'язковим.",
        messageHex: "Шеллкод має бути валідним HEX рядком."
    },
    "powershellScriptUrl": { 
        requiredIf: "powershell_downloader_stager", 
        isUrl: true,
        messageRequired: "URL PowerShell скрипта є обов'язковим.",
        messageUrl: "Невірний формат URL для PowerShell скрипта."
    },
    "c2DnsZone": { 
        requiredIf: "dns_beacon_c2_concept", 
        isDomain: true,
        messageRequired: "DNS Зона C2 є обов'язковою.",
        messageDomain: "Невірний формат DNS зони."
    },
    "dnsBeaconSubdomainPrefix": { 
        requiredIf: "dns_beacon_c2_concept", 
        isSubdomainLabel: true, // Перевірка на валідний сегмент домену
        messageRequired: "Префікс субдомену є обов'язковим.",
        messageSubdomainLabel: "Невірний формат префіксу субдомену (тільки a-z, A-Z, 0-9, -)."
    },
    "persistenceMethod": { requiredIf: "windows_simple_persistence_stager", messageRequired: "Метод персистентності є обов'язковим."},
    "commandToPersist": { 
        requiredIf: "windows_simple_persistence_stager", 
        minLength: 1,
        messageRequired: "Команда для персистентності є обов'язковою.",
        messageMinLength: "Команда має містити хоча б 1 символ."
    },
    "artifactName": { 
        requiredIf: "windows_simple_persistence_stager", 
        minLength: 3, 
        isArtifactName: true,
        messageRequired: "Ім'я артефакту є обов'язковим.",
        messageMinLength: "Ім'я артефакту має містити хоча б 3 символи.",
        messageArtifactName: "Ім'я артефакту може містити літери, цифри, _, ., -."
    },
    "obfuscationKey": { 
        required: true, 
        minLength: 5,
        messageRequired: "Ключ обфускації є обов'язковим.",
        messageMinLength: "Ключ обфускації має містити хоча б 5 символів."
    }
    // output_format та pyinstaller_options зазвичай не потребують такої жорсткої валідації на клієнті
};


/**
 * Ініціалізує елементи DOM та обробники подій для вкладки "Генератор Пейлоадів".
 */
function initializePayloadGeneratorEvents() {
    payloadForm = document.getElementById('payloadGeneratorForm');
    payloadArchetypeSelect = document.getElementById('payloadArchetype');
    archetypeParamsContainer = document.getElementById('archetypeParamsContainer');
    payloadOutputSection = document.getElementById('payloadOutputSection');
    payloadStagerOutput = document.getElementById('payloadStagerOutput');
    payloadGenerationLog = document.getElementById('payloadGenerationLog');
    generatePayloadButton = document.getElementById('generatePayloadButton');
    outputFormatSelect = document.getElementById('outputFormat');
    pyinstallerOptionsContainer = document.getElementById('pyinstallerOptionsContainer');
    enableStagerDebugPrintsCheckbox = document.getElementById('enableStagerDebugPrints');

    if (!payloadForm || !payloadArchetypeSelect || !generatePayloadButton) {
        console.error("Ключові елементи форми генератора пейлоадів не знайдено!");
        return;
    }

    // Динамічне відображення секцій параметрів залежно від обраного архетипу
    payloadArchetypeSelect.addEventListener('change', function() {
        const selectedArchetype = this.value;
        if(payloadGenerationLog) payloadGenerationLog.textContent = ''; // Очищаємо лог при зміні
        if(payloadOutputSection) payloadOutputSection.classList.add('hidden'); // Ховаємо вивід

        // Сховати всі секції параметрів
        if (archetypeParamsContainer) {
            Array.from(archetypeParamsContainer.children).forEach(section => {
                if (section.matches('.form-section')) { // Переконуємося, що це секція параметрів
                    section.classList.add('hidden');
                }
            });
        }
        
        // Показати релевантну секцію
        if (selectedArchetype && payloadParamSectionsConfigFE[selectedArchetype]) {
            const sectionToShowId = payloadParamSectionsConfigFE[selectedArchetype].sectionId;
            const sectionToShow = document.getElementById(sectionToShowId);
            if (sectionToShow) {
                sectionToShow.classList.remove('hidden');
            }
        }
        clearAllErrors('payloadGeneratorForm'); // Очищаємо помилки валідації
    });

    // Показ/приховування опцій PyInstaller
    if (outputFormatSelect && pyinstallerOptionsContainer) {
        outputFormatSelect.addEventListener('change', function() {
            if (this.value === 'pyinstaller_exe_windows') {
                pyinstallerOptionsContainer.classList.remove('hidden');
            } else {
                pyinstallerOptionsContainer.classList.add('hidden');
            }
        });
        // Ініціалізація стану при завантаженні
        if (outputFormatSelect.value === 'pyinstaller_exe_windows') {
            pyinstallerOptionsContainer.classList.remove('hidden');
        } else {
            pyinstallerOptionsContainer.classList.add('hidden');
        }
    }
    
    // Обробник відправки форми
    payloadForm.addEventListener('submit', handlePayloadFormSubmit);

    // Початкове налаштування видимості секцій (на випадок, якщо щось обрано за замовчуванням)
    if (payloadArchetypeSelect.value) {
        payloadArchetypeSelect.dispatchEvent(new Event('change'));
    }
}

/**
 * Валідує форму генератора пейлоадів на стороні клієнта.
 * @param {FormData} formData - Дані форми.
 * @returns {boolean} - True, якщо форма валідна, інакше false.
 */
function validatePayloadFormClientSide(formData) {
    clearAllErrors('payloadGeneratorForm'); // Використовуємо ui_utils.js
    let isValid = true;
    const currentArchetype = formData.get('payload_archetype');

    for (const fieldNameOriginal in payloadValidationRulesFE) {
        const rules = payloadValidationRulesFE[fieldNameOriginal];
        
        // Адаптація імен полів з HTML до ключів у payloadValidationRulesFE
        let formFieldName = fieldNameOriginal; 
        if (fieldNameOriginal === 'c2TargetHostShell') formFieldName = 'c2TargetHostShell'; // Це вже правильне ім'я з HTML
        else if (fieldNameOriginal === 'c2TargetPortShell') formFieldName = 'c2TargetPortShell';
        // ... інші специфічні перетворення, якщо потрібно ...

        const inputElement = payloadForm.elements[formFieldName]; // Шукаємо елемент за його name атрибутом
        const value = inputElement ? (inputElement.type === 'checkbox' ? inputElement.checked : String(formData.get(formFieldName) || '').trim()) : null;
        
        const errorElementId = `error-${inputElement ? inputElement.id : fieldNameOriginal.replace(/_/g, '')}`;


        let isFieldRequired = rules.required;
        if (Array.isArray(rules.requiredIf) && rules.requiredIf.includes(currentArchetype)) {
            isFieldRequired = true;
        } else if (typeof rules.requiredIf === 'string' && rules.requiredIf === currentArchetype) {
            isFieldRequired = true;
        } else if (rules.requiredIf && typeof rules.requiredIf !== 'boolean') {
             isFieldRequired = false; // Якщо requiredIf не спрацював, поле не є обов'язковим через цю умову
        }


        if (isFieldRequired && (value === null || value === '' || (value === false && inputElement && inputElement.type !== 'checkbox'))) {
            displayError(errorElementId, rules.messageRequired || "Це поле є обов'язковим.");
            isValid = false; continue;
        }

        if (value !== null && value !== '') { // Перевіряємо тільки якщо є значення
            if (rules.minLength && String(value).length < rules.minLength) {
                displayError(errorElementId, rules.messageMinLength || `Мін. довжина: ${rules.minLength}.`); isValid = false;
            }
            if (rules.isUrl && !/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/.test(String(value))) {
                displayError(errorElementId, rules.messageUrl || `Невірний формат URL.`); isValid = false;
            }
            if (rules.isHostOrIp && !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$/.test(String(value))) {
                 displayError(errorElementId, rules.messageHostOrIp || `Очікується IP або домен.`); isValid = false;
            }
            if (rules.isPort) {
                const portNum = parseInt(String(value), 10);
                if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                    displayError(errorElementId, rules.messagePort || `Порт має бути числом від 1 до 65535.`); isValid = false;
                }
            }
            if (rules.isHex && value !== "DEADBEEFCAFE" && !/^[0-9a-fA-F]*$/.test(String(value).replace(/\s/g, ''))) { // Дозволяємо DEADBEEFCAFE як валідний плейсхолдер
                displayError(errorElementId, rules.messageHex || `Очікується HEX рядок.`); isValid = false;
            }
            if (rules.isDomain && !/^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$/.test(String(value))) {
                 displayError(errorElementId, rules.messageDomain || `Невірний формат домену.`); isValid = false;
            }
            if (rules.isSubdomainLabel && !/^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/.test(String(value))) { // RFC 1035 label
                 displayError(errorElementId, rules.messageSubdomainLabel || `Невірний формат мітки субдомену.`); isValid = false;
            }
            if (rules.isArtifactName && !/^[a-zA-Z0-9_.-]+$/.test(String(value))) {
                displayError(errorElementId, rules.messageArtifactName || `Дозволені символи: a-z, A-Z, 0-9, _, ., -`); isValid = false;
            }
        }
    }
    return isValid;
}


/**
 * Обробляє відправку форми генератора пейлоадів.
 * @param {Event} event - Подія відправки форми.
 */
async function handlePayloadFormSubmit(event) {
    event.preventDefault();
    if (!generatePayloadButton || !payloadOutputSection || !payloadStagerOutput || !payloadGenerationLog) return;

    setButtonLoadingState(generatePayloadButton, true, 'Згенерувати Пейлоад'); // Використовуємо ui_utils.js
    
    const formData = new FormData(payloadForm);
    
    if (!validatePayloadFormClientSide(formData)) {
        logToUITextArea(payloadGenerationLog.id, '[CLIENT_VALIDATION_FAILURE] Будь ласка, виправте помилки у формі.');
        payloadOutputSection.classList.add('hidden');
        setButtonLoadingState(generatePayloadButton, false, 'Згенерувати Пейлоад');
        return;
    }

    let params = {};
    const currentArchetype = formData.get('payload_archetype');
    params['payload_archetype'] = currentArchetype;

    // Збираємо параметри з форми
    for (const [key, value] of formData.entries()) {
        if (key === 'payload_archetype') continue;

        // Обробка чекбоксів
        const checkboxElement = payloadForm.elements[key];
        if (checkboxElement && checkboxElement.type === 'checkbox') {
            params[key] = checkboxElement.checked;
            continue;
        }

        // Спеціальна обробка для полів, які залежать від архетипу
        let relevantFieldsForArchetype = [];
        if (currentArchetype && payloadParamSectionsConfigFE[currentArchetype]) {
            relevantFieldsForArchetype = payloadParamSectionsConfigFE[currentArchetype].fields.map(f => {
                // Адаптуємо імена полів з HTML до тих, що очікує backend (якщо вони відрізняються)
                if (f === 'c2TargetHostShell') return 'c2_target_host';
                if (f === 'c2TargetPortShell') return 'c2_target_port';
                if (f === 'shellcodeHexPlaceholder') return 'shellcode_hex_placeholder';
                // ... інші специфічні перетворення ...
                return f; // Якщо імена співпадають
            });
        }
        
        // Перетворюємо HTML імена полів на ті, що очікує backend
        let backendKey = key;
        if (key === 'c2TargetHostShell') backendKey = 'c2_target_host';
        else if (key === 'c2TargetPortShell') backendKey = 'c2_target_port';
        // ... інші перетворення ...

        // Додаємо параметр, якщо він релевантний для поточного архетипу або є загальним
        const isArchetypeSpecificField = payloadParamSectionsConfigFE[currentArchetype]?.fields.includes(key);
        const isGeneralField = ['obfuscation_key', 'output_format', 'pyinstaller_options', 
                                'enable_stager_metamorphism', 'enable_evasion_checks',
                                'enable_stager_debug_prints',
                                'enable_amsi_bypass_concept', 'enable_disk_size_check'].includes(key);

        if (isArchetypeSpecificField || isGeneralField) {
            if (backendKey === 'c2_target_port' && value) { // Конвертуємо порт в число
                 params[backendKey] = parseInt(value, 10);
            } else {
                 params[backendKey] = value;
            }
        }
    }
    // Переконуємося, що всі булеві параметри передані коректно
    ['enable_stager_metamorphism', 'enable_evasion_checks', 'enable_amsi_bypass_concept', 
     'enable_disk_size_check', 'enable_stager_debug_prints'].forEach(cbName => {
        const cbElement = document.getElementById(cbName);
        if (cbElement) params[cbName] = cbElement.checked;
    });


    logToUITextArea(payloadGenerationLog.id, `[GUI_INFO] Відправка запиту на ${API_BASE_URL}/payload/generate ...`);
    logToUITextArea(payloadGenerationLog.id, `Параметри: ${JSON.stringify(params, null, 2)}`);
    payloadStagerOutput.textContent = 'Очікування відповіді від backend...';
    payloadOutputSection.classList.remove('hidden');

    try {
        const response = await fetch(`${API_BASE_URL}/payload/generate`, { // Використовуємо API_BASE_URL з api.js
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params),
        });
        const responseData = await response.json();
        
        // Очищаємо попередній лог перед виведенням нового
        payloadGenerationLog.textContent = ''; 
        logToUITextArea(payloadGenerationLog.id, responseData.generationLog || "Лог генерації не отримано від backend.");

        if (response.ok && responseData.success) {
            payloadStagerOutput.textContent = responseData.stagerCode;
        } else {
            let errorText = `Помилка від backend: ${responseData.error || response.statusText || 'Невідома помилка'}`;
            if (responseData.errors) { // Серверні помилки валідації
                errorText += "\nДеталі валідації: \n" + responseData.errors.map(err => `  - ${err}`).join("\n");
            }
            payloadStagerOutput.textContent = errorText;
            logToUITextArea(payloadGenerationLog.id, errorText, true);
        }
    } catch (error) {
        const errorMsg = `[GUI_ERROR] Помилка мережевого запиту до backend: ${error.message || error}`;
        logToUITextArea(payloadGenerationLog.id, errorMsg, true);
        payloadStagerOutput.textContent = `Помилка зв'язку з backend. Деталі в консолі та логах GUI.`;
        console.error("Payload generation fetch error:", error);
    } finally {
        setButtonLoadingState(generatePayloadButton, false, 'Згенерувати Пейлоад');
    }
}

/**
 * Завантажує список архетипів з backend та заповнює select.
 */
async function fetchPayloadArchetypes() {
    if (payloadArchetypesLoaded) {
        console.log("[PayloadUI] Архетипи вже завантажені.");
        return;
    }
    if (!payloadArchetypeSelect) return;

    console.log("[PayloadUI] Завантаження архетипів...");
    try {
        // Припускаємо, що API_BASE_URL вже визначено в api.js
        const response = await fetch(`${API_BASE_URL}/payload/archetypes`);
        const data = await response.json();

        if (data.success && data.archetypes) {
            payloadArchetypeSelect.innerHTML = '<option value="">-- Оберіть архетип --</option>'; // Очистити старі та додати дефолтну
            data.archetypes.forEach(archetype => {
                const option = document.createElement('option');
                option.value = archetype.name;
                option.textContent = archetype.description || archetype.name;
                payloadArchetypeSelect.appendChild(option);
            });
            console.log("[PayloadUI] Архетипи успішно завантажені.");
            payloadArchetypesLoaded = true; // Встановлюємо прапорець після успішного завантаження
            // Після завантаження архетипів, ініціалізуємо видимість секцій
            if (payloadArchetypeSelect.value) {
                 payloadArchetypeSelect.dispatchEvent(new Event('change'));
            }
        } else {
            console.error("[PayloadUI] Помилка завантаження архетипів:", data.error || "Невідома помилка.");
            logToUITextArea(payloadGenerationLog.id, `Помилка завантаження архетипів: ${data.error || "Невідома помилка."}`, true);
        }
    } catch (error) {
        console.error("[PayloadUI] Мережева помилка при завантаженні архетипів:", error);
        logToUITextArea(payloadGenerationLog.id, `Мережева помилка при завантаженні архетипів: ${error.message}`, true);
    }
}


// Ініціалізація при завантаженні скрипта (буде викликана з main.js)
// initializePayloadGeneratorEvents(); // Цей виклик буде в main.js
// fetchPayloadArchetypes(); // Також може бути викликано з main.js після ініціалізації DOM
