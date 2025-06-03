// File: CYBER_DASHBOARD_FRONTEND/js/payload_generator_ui.js
// Координатор: Синтаксис
// Опис: Додано обробку нових параметрів enable_stager_logging та strip_stager_metadata.

// --- DOM Елементи ---
let payloadForm, payloadArchetypeSelect, archetypeParamsContainer,
    payloadOutputSection, payloadStagerOutput, payloadGenerationLog,
    generatePayloadButton, outputFormatSelect, pyinstallerOptionsContainer,
    // Нові елементи для чекбоксів
    enableStagerLoggingCheckbox, stripStagerMetadataCheckbox;


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
        isHex: true, 
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
        isSubdomainLabel: true, 
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
};


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

    // Ініціалізація нових чекбоксів
    enableStagerLoggingCheckbox = document.getElementById('enableStagerLogging');
    stripStagerMetadataCheckbox = document.getElementById('stripStagerMetadata');


    if (!payloadForm || !payloadArchetypeSelect || !generatePayloadButton || !enableStagerLoggingCheckbox || !stripStagerMetadataCheckbox) {
        console.error("Ключові елементи форми генератора пейлоадів не знайдено!");
        return;
    }

    payloadArchetypeSelect.addEventListener('change', function() {
        const selectedArchetype = this.value;
        if(payloadGenerationLog) payloadGenerationLog.textContent = ''; 
        if(payloadOutputSection) payloadOutputSection.classList.add('hidden'); 

        if (archetypeParamsContainer) {
            Array.from(archetypeParamsContainer.children).forEach(section => {
                if (section.matches('.form-section')) { 
                    section.classList.add('hidden');
                }
            });
        }
        
        if (selectedArchetype && payloadParamSectionsConfigFE[selectedArchetype]) {
            const sectionToShowId = payloadParamSectionsConfigFE[selectedArchetype].sectionId;
            const sectionToShow = document.getElementById(sectionToShowId);
            if (sectionToShow) {
                sectionToShow.classList.remove('hidden');
            }
        }
        clearAllErrors('payloadGeneratorForm'); 
    });

    if (outputFormatSelect && pyinstallerOptionsContainer) {
        outputFormatSelect.addEventListener('change', function() {
            if (this.value === 'pyinstaller_exe_windows') {
                pyinstallerOptionsContainer.classList.remove('hidden');
            } else {
                pyinstallerOptionsContainer.classList.add('hidden');
            }
        });
        if (outputFormatSelect.value === 'pyinstaller_exe_windows') {
            pyinstallerOptionsContainer.classList.remove('hidden');
        } else {
            pyinstallerOptionsContainer.classList.add('hidden');
        }
    }
    
    payloadForm.addEventListener('submit', handlePayloadFormSubmit);

    if (payloadArchetypeSelect.value) {
        payloadArchetypeSelect.dispatchEvent(new Event('change'));
    }
}

function validatePayloadFormClientSide(formData) {
    // ... (існуюча логіка валідації залишається без змін) ...
    clearAllErrors('payloadGeneratorForm'); 
    let isValid = true;
    const currentArchetype = formData.get('payload_archetype');

    for (const fieldNameOriginal in payloadValidationRulesFE) {
        const rules = payloadValidationRulesFE[fieldNameOriginal];
        
        let formFieldName = fieldNameOriginal; 
        // ... (специфічні перетворення імен полів) ...

        const inputElement = payloadForm.elements[formFieldName]; 
        const value = inputElement ? (inputElement.type === 'checkbox' ? inputElement.checked : String(formData.get(formFieldName) || '').trim()) : null;
        const errorElementId = `error-${inputElement ? inputElement.id : fieldNameOriginal.replace(/_/g, '')}`;

        let isFieldRequired = rules.required;
        if (Array.isArray(rules.requiredIf) && rules.requiredIf.includes(currentArchetype)) {
            isFieldRequired = true;
        } else if (typeof rules.requiredIf === 'string' && rules.requiredIf === currentArchetype) {
            isFieldRequired = true;
        } else if (rules.requiredIf && typeof rules.requiredIf !== 'boolean') {
             isFieldRequired = false; 
        }

        if (isFieldRequired && (value === null || value === '' || (value === false && inputElement && inputElement.type !== 'checkbox'))) {
            displayError(errorElementId, rules.messageRequired || "Це поле є обов'язковим.");
            isValid = false; continue;
        }

        if (value !== null && value !== '') { 
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
            if (rules.isHex && value !== "DEADBEEFCAFE" && !/^[0-9a-fA-F]*$/.test(String(value).replace(/\s/g, ''))) { 
                displayError(errorElementId, rules.messageHex || `Очікується HEX рядок.`); isValid = false;
            }
            if (rules.isDomain && !/^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$/.test(String(value))) {
                 displayError(errorElementId, rules.messageDomain || `Невірний формат домену.`); isValid = false;
            }
            if (rules.isSubdomainLabel && !/^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/.test(String(value))) { 
                 displayError(errorElementId, rules.messageSubdomainLabel || `Невірний формат мітки субдомену.`); isValid = false;
            }
            if (rules.isArtifactName && !/^[a-zA-Z0-9_.-]+$/.test(String(value))) {
                displayError(errorElementId, rules.messageArtifactName || `Дозволені символи: a-z, A-Z, 0-9, _, ., -`); isValid = false;
            }
        }
    }
    return isValid;
}


async function handlePayloadFormSubmit(event) {
    event.preventDefault();
    if (!generatePayloadButton || !payloadOutputSection || !payloadStagerOutput || !payloadGenerationLog) return;

    setButtonLoadingState(generatePayloadButton, true, 'Згенерувати Пейлоад');
    
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

    for (const [key, value] of formData.entries()) {
        if (key === 'payload_archetype') continue;

        const checkboxElement = payloadForm.elements[key];
        if (checkboxElement && checkboxElement.type === 'checkbox') {
            // Для чекбоксів name атрибут має відповідати ключам, які очікує backend
            // Наприклад, enable_stager_logging, strip_stager_metadata
            params[key] = checkboxElement.checked; 
            continue;
        }
        
        let backendKey = key;
        if (key === 'c2TargetHostShell') backendKey = 'c2_target_host';
        else if (key === 'c2TargetPortShell') backendKey = 'c2_target_port';
        // ... інші перетворення ...

        const isArchetypeSpecificField = payloadParamSectionsConfigFE[currentArchetype]?.fields.includes(key);
        // Додаємо нові параметри до загальних полів
        const isGeneralField = ['obfuscation_key', 'output_format', 'pyinstaller_options', 
                                'enable_stager_metamorphism', 'enable_evasion_checks', 
                                'enable_amsi_bypass_concept', 'enable_disk_size_check',
                                'enable_stager_logging', 'strip_stager_metadata' // Нові параметри
                               ].includes(key);


        if (isArchetypeSpecificField || isGeneralField) {
            if (backendKey === 'c2_target_port' && value) { 
                 params[backendKey] = parseInt(value, 10);
            } else {
                 params[backendKey] = value;
            }
        }
    }
    // Переконуємося, що всі булеві параметри (чекбокси) передані коректно,
    // оскільки FormData може не включати їх, якщо вони не відмічені.
    const checkboxNames = [
        'enable_stager_metamorphism', 'enable_evasion_checks', 
        'enable_amsi_bypass_concept', 'enable_disk_size_check',
        'enable_stager_logging', 'strip_stager_metadata'
    ];
    checkboxNames.forEach(cbName => {
        const cbElement = document.getElementById(cbName.replace(/_/g, (match, offset) => offset === 0 ? match : match.toUpperCase())); // Відновлення camelCase ID
        // Або, якщо ID елементів точно співпадають з name (з підкресленнями):
        // const cbElement = document.getElementById(cbName); 
        // Для надійності, використовуємо атрибут name для пошуку, якщо ID неточні
        const cbElementByName = payloadForm.elements[cbName];
        if (cbElementByName && cbElementByName.type === 'checkbox') {
            params[cbName] = cbElementByName.checked;
        } else if (cbElement && cbElement.type === 'checkbox') { // Резервний варіант, якщо ID використовується
             params[cbName] = cbElement.checked;
        } else if (params[cbName] === undefined) { // Якщо параметр не був доданий з formData (не відмічений)
            params[cbName] = false; // Встановлюємо false за замовчуванням для невідмічених чекбоксів
        }
    });


    logToUITextArea(payloadGenerationLog.id, `[GUI_INFO] Відправка запиту на ${API_BASE_URL}/payload/generate ...`);
    logToUITextArea(payloadGenerationLog.id, `Параметри: ${JSON.stringify(params, null, 2)}`);
    payloadStagerOutput.textContent = 'Очікування відповіді від backend...';
    payloadOutputSection.classList.remove('hidden');

    try {
        const response = await fetch(`${API_BASE_URL}/payload/generate`, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params),
        });
        const responseData = await response.json();
        
        payloadGenerationLog.textContent = ''; 
        logToUITextArea(payloadGenerationLog.id, responseData.generationLog || "Лог генерації не отримано від backend.");

        if (response.ok && responseData.success) {
            payloadStagerOutput.textContent = responseData.stagerCode;
        } else {
            let errorText = `Помилка від backend: ${responseData.error || response.statusText || 'Невідома помилка'}`;
            if (responseData.errors) { 
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

async function fetchPayloadArchetypes() {
    // ... (існуюча логіка залишається без змін) ...
    if (!payloadArchetypeSelect) return;

    console.log("[PayloadUI] Завантаження архетипів...");
    try {
        const response = await fetch(`${API_BASE_URL}/payload/archetypes`);
        const data = await response.json();

        if (data.success && data.archetypes) {
            payloadArchetypeSelect.innerHTML = '<option value="">-- Оберіть архетип --</option>'; 
            data.archetypes.forEach(archetype => {
                const option = document.createElement('option');
                option.value = archetype.name;
                option.textContent = archetype.description || archetype.name;
                payloadArchetypeSelect.appendChild(option);
            });
            console.log("[PayloadUI] Архетипи успішно завантажені.");
            if (payloadArchetypeSelect.value) {
                 payloadArchetypeSelect.dispatchEvent(new Event('change'));
            }
        } else {
            console.error("[PayloadUI] Помилка завантаження архетипів:", data.error || "Невідома помилка.");
            if(payloadGenerationLog) logToUITextArea(payloadGenerationLog.id, `Помилка завантаження архетипів: ${data.error || "Невідома помилка."}`, true);
        }
    } catch (error) {
        console.error("[PayloadUI] Мережева помилка при завантаженні архетипів:", error);
        if(payloadGenerationLog) logToUITextArea(payloadGenerationLog.id, `Мережева помилка при завантаженні архетипів: ${error.message}`, true);
    }
}
