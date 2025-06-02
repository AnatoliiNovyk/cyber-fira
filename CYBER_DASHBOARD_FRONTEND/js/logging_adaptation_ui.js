// js/logging_adaptation_ui.js
// UI логіка для вкладки "Логи & Адаптація"

// --- DOM Елементи ---
let loggingAdaptationTab, aggregatedLogsOutput, refreshLogsButtonLA,
    statsSuccessRate, statsDetectionRate, statsBestArchetype, statsActiveImplantsLA,
    autoAdaptRulesCheckbox, applyRuleChangesButton, ruleToUpdateInput, newRuleValueInput;

/**
 * Ініціалізує елементи DOM та обробники подій для вкладки "Логи & Адаптація".
 */
function initializeLoggingAdaptationEvents() {
    loggingAdaptationTab = document.getElementById('loggingAdaptationTab');
    aggregatedLogsOutput = document.getElementById('aggregatedLogsOutput');
    refreshLogsButtonLA = document.getElementById('refreshLogsButtonLA');
    
    statsSuccessRate = document.getElementById('statsSuccessRate');
    statsDetectionRate = document.getElementById('statsDetectionRate');
    statsBestArchetype = document.getElementById('statsBestArchetype');
    statsActiveImplantsLA = document.getElementById('statsActiveImplantsLA');
    
    autoAdaptRulesCheckbox = document.getElementById('autoAdaptRules');
    applyRuleChangesButton = document.getElementById('applyRuleChangesButton');
    ruleToUpdateInput = document.getElementById('ruleToUpdate');
    newRuleValueInput = document.getElementById('newRuleValue');

    if (!aggregatedLogsOutput || !refreshLogsButtonLA || !applyRuleChangesButton) {
        console.error("Ключові елементи вкладки 'Логи & Адаптація' не знайдено!");
        return;
    }

    refreshLogsButtonLA.addEventListener('click', fetchOperationalData);
    applyRuleChangesButton.addEventListener('click', handleApplyRuleChanges);

    // Початкове повідомлення в логах, якщо вони порожні
    if (aggregatedLogsOutput && !aggregatedLogsOutput.hasChildNodes()) {
        aggregatedLogsOutput.innerHTML = '<p class="text-gray-400">Натисніть "Оновити Логи" для завантаження.</p>';
    }
}

/**
 * Завантажує оперативні дані (логи та статистику) з backend.
 */
async function fetchOperationalData() {
    if (!aggregatedLogsOutput || !statsSuccessRate || !refreshLogsButtonLA) return;

    setButtonLoadingState(refreshLogsButtonLA, true, 'Оновити Логи');
    logToLoggingAdaptationUI("[GUI_LOG_ADAPT] Запит оперативних даних з backend...", false, true); // Очистити попередні GUI логи

    try {
        const response = await fetch(`${API_BASE_URL}/data/operational`); // Використовуємо API_BASE_URL
        const data = await response.json();

        if (data.log) { // Логи від backend
            data.log.split('\n').forEach(line => logToLoggingAdaptationUI(`[BE_LOG] ${line}`));
        }

        if (data.success) {
            // Відображення агрегованих логів
            aggregatedLogsOutput.innerHTML = ''; // Очистити поточні логи
            if (data.aggregatedLogs && data.aggregatedLogs.length > 0) {
                data.aggregatedLogs.forEach(log => {
                    const logEntryDiv = document.createElement('div');
                    logEntryDiv.className = 'log-entry'; // Базовий клас
                    let logClass = 'log-info'; // За замовчуванням
                    if (log.level === "WARN") logClass = 'log-warning';
                    else if (log.level === "ERROR") logClass = 'log-error';
                    else if (log.level === "SUCCESS") logClass = 'log-success';
                    else if (log.level === "DEBUG") logClass = 'text-sky-400'; // Приклад для DEBUG

                    logEntryDiv.innerHTML = `
                        <span class="font-mono text-xs ${logClass}">[${log.timestamp}][${log.level}]</span>
                        <span class="font-mono text-xs text-purple-400">[${log.component}]</span>
                        <span class="ml-1 ${logClass}">${log.message}</span>
                    `;
                    aggregatedLogsOutput.appendChild(logEntryDiv);
                });
                aggregatedLogsOutput.scrollTop = 0; // Прокрутка до верху, щоб бачити новіші логи
            } else {
                aggregatedLogsOutput.innerHTML = '<p class="text-gray-400">Агрегованих логів не знайдено від backend.</p>';
            }

            // Відображення статистики
            if (data.statistics) {
                const stats = data.statistics;
                if(statsSuccessRate) statsSuccessRate.textContent = `${stats.successRate || '--'}%`;
                if(statsDetectionRate) statsDetectionRate.textContent = `${stats.detectionRate || '--'}%`;
                if(statsBestArchetype) statsBestArchetype.textContent = stats.bestArchetype || 'N/A';
                if(statsActiveImplantsLA) statsActiveImplantsLA.textContent = stats.activeImplants !== undefined ? stats.activeImplants.toString() : '0';
                
                // Можна додати відображення нової "просунутої" статистики, якщо елементи є в HTML
                // const avgDwellTimeEl = document.getElementById('statsAvgDwellTime');
                // if (avgDwellTimeEl) avgDwellTimeEl.textContent = `${stats.avgDwellTimeHours || '--'} год.`;
            } else {
                 setDefaultStats();
            }
            logToLoggingAdaptationUI("[GUI_LOG_ADAPT] Оперативні дані успішно оновлено.");
        } else {
            logToLoggingAdaptationUI(`[GUI_LOG_ADAPT_ERROR] Помилка отримання оперативних даних: ${data.error || 'Невідома помилка backend'}`, true);
            setDefaultStats();
            if (aggregatedLogsOutput) aggregatedLogsOutput.innerHTML = '<p class="text-red-400">Не вдалося завантажити логи.</p>';
        }
    } catch (error) {
        logToLoggingAdaptationUI(`[GUI_LOG_ADAPT_ERROR] Помилка мережевого запиту для оперативних даних: ${error.message}`, true);
        setDefaultStats();
        if (aggregatedLogsOutput) aggregatedLogsOutput.innerHTML = '<p class="text-red-400">Помилка зв\'язку з backend для логів.</p>';
        console.error("Fetch operational data error:", error);
    } finally {
        setButtonLoadingState(refreshLogsButtonLA, false, 'Оновити Логи');
    }
}

/**
 * Встановлює значення статистики за замовчуванням.
 */
function setDefaultStats() {
    if(statsSuccessRate) statsSuccessRate.textContent = '--%';
    if(statsDetectionRate) statsDetectionRate.textContent = '--%';
    if(statsBestArchetype) statsBestArchetype.textContent = 'N/A';
    if(statsActiveImplantsLA) statsActiveImplantsLA.textContent = '0';
}

/**
 * Обробляє відправку форми для оновлення правил фреймворку.
 */
async function handleApplyRuleChanges() {
    if (!applyRuleChangesButton || !ruleToUpdateInput || !newRuleValueInput || !autoAdaptRulesCheckbox) return;

    setButtonLoadingState(applyRuleChangesButton, true, 'Застосувати Зміни');
    
    const ruleId = ruleToUpdateInput.value.trim() || "DEFAULT_RULE_ID_FROM_GUI";
    const newValue = newRuleValueInput.value.trim() || "DEFAULT_NEW_VALUE_FROM_GUI";
    const autoAdapt = autoAdaptRulesCheckbox.checked;

    logToLoggingAdaptationUI(`[GUI_RULES] Надсилання запиту на оновлення правила '${ruleId}' на значення '${newValue}'. Авто-адаптація: ${autoAdapt}`);

    try {
        const response = await fetch(`${API_BASE_URL}/data/framework_rules`, { // Використовуємо API_BASE_URL
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                auto_adapt_rules: autoAdapt,
                rule_id: ruleId,
                new_value: newValue
            }),
        });
        const responseData = await response.json();

        if (responseData.log) { // Логи від backend
             responseData.log.split('\n').forEach(line => logToLoggingAdaptationUI(`[BE_LOG] ${line}`));
        }

        if (response.ok && responseData.success) {
            logToLoggingAdaptationUI(`[GUI_RULES_SUCCESS] ${responseData.message || "Правила успішно оновлено (симуляція)."}`);
            // Опціонально: очистити поля форми
            // ruleToUpdateInput.value = '';
            // newRuleValueInput.value = '';
        } else {
            logToLoggingAdaptationUI(`[GUI_RULES_ERROR] Помилка оновлення правил: ${responseData.error || 'Невідома помилка backend'}`, true);
        }
    } catch (error) {
        logToLoggingAdaptationUI(`[GUI_RULES_ERROR] Помилка мережевого запиту для оновлення правил: ${error.message}`, true);
        console.error("Update framework rules fetch error:", error);
    } finally {
        setButtonLoadingState(applyRuleChangesButton, false, 'Застосувати Зміни');
    }
}

/**
 * Допоміжна функція для логування в область виводу логів цієї вкладки.
 * @param {string} message - Повідомлення для логування.
 * @param {boolean} [isError=false] - Якщо true, повідомлення може бути стилізовано як помилка.
 * @param {boolean} [clearPrevious=false] - Якщо true, очистити попередні логи GUI перед додаванням нового.
 */
function logToLoggingAdaptationUI(message, isError = false, clearPrevious = false) {
    // Використовуємо загальну функцію з ui_utils.js, але для specific log area
    // Припускаємо, що aggregatedLogsOutput використовується і для GUI логів цієї вкладки, або потрібна окрема область
    const logArea = aggregatedLogsOutput; // Або інший ID, якщо є окрема область для GUI логів
    if (logArea) {
        if (clearPrevious) {
            logArea.innerHTML = ''; // Очищаємо, якщо потрібно
        }
        const timestamp = new Date().toLocaleTimeString();
        const prefix = `[${timestamp}] `;
        
        const entryDiv = document.createElement('div');
        entryDiv.className = 'log-entry'; // Можна додати специфічний клас для GUI логів
        entryDiv.style.color = isError ? '#F87171' : '#60A5FA'; // Синій для GUI логів, червоний для помилок
        entryDiv.textContent = prefix + message;
        
        // Додаємо новий лог на початок (якщо це aggregatedLogsOutput)
        if (logArea.firstChild && logArea.id === 'aggregatedLogsOutput') {
             logArea.insertBefore(entryDiv, logArea.firstChild);
        } else {
             logArea.appendChild(entryDiv);
        }
        if(logArea.id !== 'aggregatedLogsOutput') logArea.scrollTop = logArea.scrollHeight;


    } else {
        console.log(`LOG_ADAPT_UI: ${message}`);
    }
}

/**
 * Оновлює відображення кількості активних імплантів на цій вкладці.
 * Ця функція викликається з c2_control_ui.js після оновлення списку імплантів.
 * @param {number} count - Кількість активних імплантів.
 */
function updateActiveImplantsStats(count) {
    if (statsActiveImplantsLA) {
        statsActiveImplantsLA.textContent = count.toString();
        logToLoggingAdaptationUI(`[STATS_UPDATE] Кількість активних імплантів оновлено: ${count}`);
    }
}


// Ініціалізація при завантаженні скрипта (буде викликана з main.js)
// initializeLoggingAdaptationEvents();
// fetchOperationalData(); // Може бути викликано з main.js при активації вкладки
