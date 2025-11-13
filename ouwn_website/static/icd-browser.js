<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Add Medical Note & ICD Codes</title>
  <link rel="stylesheet" href="/static/style.css">
  <style>
    .icd-container { margin-top: 20px; padding: 10px; border: 1px solid #ccc; }
    .result-item { margin: 5px 0; }
    #submitBtn { margin-top: 10px; }
  </style>
</head>
<body class="form-page medical-note">
  {% include "header.html" %}

  <nav class="ouwn-breadcrumb-bar" role="navigation" aria-label="Breadcrumb">
    <div class="ouwn-crumbs">
      <a class="crumb" href="{{ url_for('dashboard') }}">
        <i class="fa-solid fa-house"></i>
        <span>Dashboard</span>
      </a>
      <span class="sep" aria-hidden="true">/</span>
      <span class="crumb current" aria-current="page">
        <i class="fa-solid fa-file-medical"></i>
        <span>Add Medical Notes</span>
      </span>
    </div>
  </nav>

  <main class="container">
    {% if errors %}
      <div class="alert error">
        <ul>
          {% for e in errors %}
            <li>{{ e }}</li>
          {% endfor %}
        </ul>
      </div>
    {% endif %}

    {% if messages %}
      <div class="alert success">
        <ul>
          {% for m in messages %}
            <li>{{ m }}</li>
          {% endfor %}
        </ul>
      </div>
    {% endif %}

    <h1>Add Medical Note</h1>
    <form id="noteForm" class="card" method="POST" action="">
      <div class="row">
        <label for="pid">National ID / Iqama <span class="required">*</span></label>
        <input name="pid" id="pid" type="text" style="background-color: lightgray;"
               value="{{ prefilled_pid }}" readonly required />
      </div>

      <div class="row">
        <label for="note_text">Note <span class="required">*</span></label>
        <textarea name="note_text" id="note_text" rows="6" required>{{ note_text }}</textarea>
      </div>

      <div class="row actions">
        <button type='submit'>Add Note</button>
      </div>
    </form>

    <!-- ICD Code Browser -->
    <div class="icd-container">
      <h2>🔍 ICD Code Browser</h2>
      <input type="text" id="searchInput" placeholder="Search ICD code or description...">

      <div id="tabsList" class="tabs-list"></div>
      <div id="tabsContent" class="tabs-content"></div>

      <div id="selectedCodesContainer" style="display:none;">
        <h3>Selected Codes (<span id="selectedCount">0</span>)</h3>
        <div id="selectedCodesList"></div>
        <button id="submitBtn" type="button" onclick="submitCodes()">Submit Selected Codes</button>
      </div>
    </div>
  </main>

  <footer>
    <p>&copy; 2025 OuwN. All Rights Reserved.</p>
  </footer>

  <!-- 🔸 Combined Script -->
  <script>
    // --- Local ICD Browser ---
    let icdData = [];
    let selectedCodes = [];
    let currentTab = 'all';
    let searchTerm = '';

    const searchInput = document.getElementById('searchInput');
    const selectedCodesContainer = document.getElementById('selectedCodesContainer');
    const selectedCodesList = document.getElementById('selectedCodesList');
    const selectedCount = document.getElementById('selectedCount');
    const tabsList = document.getElementById('tabsList');
    const tabsContent = document.getElementById('tabsContent');

    async function loadData() {
      try {
        const response = await fetch('/static/icd_data.json');
        icdData = await response.json();
        initializeUI();
      } catch (error) {
        console.error('Error loading ICD data:', error);
      }
    }

    function initializeUI() {
      createTabs();
      renderCurrentTab();
      setupEventListeners();
    }

    function createTabs() {
      const allTab = createTabButton('all', 'All Categories');
      tabsList.appendChild(allTab);

      icdData.forEach((category, index) => {
        const tabButton = createTabButton(`category-${index}`, truncateText(category.Category, 25));
        tabsList.appendChild(tabButton);
      });

      const allPanel = createTabPanel('all');
      tabsContent.appendChild(allPanel);
      icdData.forEach((category, index) => {
        const panel = createTabPanel(`category-${index}`);
        tabsContent.appendChild(panel);
      });

      activateTab('all');
    }

    function createTabButton(id, text) {
      const button = document.createElement('button');
      button.className = 'tab-trigger';
      button.dataset.tab = id;
      button.textContent = text;
      button.addEventListener('click', () => activateTab(id));
      return button;
    }

    function createTabPanel(id) {
      const panel = document.createElement('div');
      panel.className = 'tab-panel';
      panel.dataset.panel = id;
      return panel;
    }

    function activateTab(tabId) {
      currentTab = tabId;
      document.querySelectorAll('.tab-trigger').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
      });
      document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.dataset.panel === tabId);
      });
      renderCurrentTab();
    }

    function renderCurrentTab() {
      const panel = document.querySelector(`.tab-panel[data-panel="${currentTab}"]`);
      if (!panel) return;
      panel.innerHTML = '';
      const container = document.createElement('div');
      container.className = 'codes-container';

      let codesToRender = [];
      if (currentTab === 'all') {
        codesToRender = icdData.flatMap(category => category.Codes);
      } else {
        const categoryIndex = parseInt(currentTab.split('-')[1]);
        codesToRender = icdData[categoryIndex].Codes;
      }

      codesToRender = filterCodes(codesToRender);
      if (codesToRender.length === 0) {
        container.appendChild(createEmptyState(searchTerm));
      } else {
        const codesList = createCodesList(codesToRender);
        container.appendChild(codesList);
      }
      panel.appendChild(container);
    }

    function filterCodes(codes) {
      if (!searchTerm) return codes;
      const searchLower = searchTerm.toLowerCase();
      return codes.filter(code =>
        code.Code.toLowerCase().includes(searchLower) ||
        code.Description.toLowerCase().includes(searchLower)
      );
    }

    function createCodesList(codes) {
      const list = document.createElement('div');
      list.className = 'codes-list';
      codes.forEach(code => list.appendChild(createCodeItem(code)));
      return list;
    }

    function createCodeItem(code) {
      const item = document.createElement('div');
      item.className = 'code-item';
      if (isCodeSelected(code)) item.classList.add('selected');

      const checkbox = document.createElement('div');
      checkbox.className = 'checkbox';
      checkbox.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
      `;

      const content = document.createElement('div');
      content.className = 'code-content';

      const badge = document.createElement('div');
      badge.className = 'code-badge';
      badge.textContent = code.Code;

      const description = document.createElement('p');
      description.className = 'code-description';
      description.textContent = code.Description;

      content.appendChild(badge);
      content.appendChild(description);
      item.appendChild(checkbox);
      item.appendChild(content);
      item.addEventListener('click', () => toggleCode(code));

      return item;
    }

    function toggleCode(code) {
      if (isCodeSelected(code)) removeCode(code);
      else selectCode(code);
    }

    function selectCode(code) {
      if (!isCodeSelected(code)) {
        selectedCodes.push(code);
        updateSelectedCodesUI();
        renderCurrentTab();
      }
    }

    function removeCode(code) {
      selectedCodes = selectedCodes.filter(c => c.Code !== code.Code);
      updateSelectedCodesUI();
      renderCurrentTab();
    }

    function isCodeSelected(code) {
      return selectedCodes.some(c => c.Code === code.Code);
    }

    function updateSelectedCodesUI() {
      if (selectedCodes.length === 0) {
        selectedCodesContainer.style.display = 'none';
      } else {
        selectedCodesContainer.style.display = 'block';
        selectedCount.textContent = selectedCodes.length;
        renderSelectedCodes();
      }
    }

    function renderSelectedCodes() {
      selectedCodesList.innerHTML = '';
      selectedCodes.forEach(code => {
        const badge = document.createElement('div');
        badge.className = 'badge';
        const codeSpan = document.createElement('span');
        codeSpan.className = 'badge-code';
        codeSpan.textContent = code.Code;
        const removeBtn = document.createElement('button');
        removeBtn.className = 'badge-remove';
        removeBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"></line>
            <line x1="6" y1="6" x2="18" y2="18"></line>
        </svg>`;
        removeBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          removeCode(code);
        });
        badge.appendChild(codeSpan);
        badge.appendChild(removeBtn);
        selectedCodesList.appendChild(badge);
      });
    }

    function setupEventListeners() {
      searchInput.addEventListener('input', (e) => {
        searchTerm = e.target.value;
        renderCurrentTab();
      });
    }

    function truncateText(text, maxLength) {
      return text.length <= maxLength ? text : text.substring(0, maxLength) + '...';
    }

    async function submitCodes() {
      if (selectedCodes.length === 0) {
        alert("Please select at least one ICD code.");
        return;
      }

      const response = await fetch("/save_codes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ codes: selectedCodes, patient_id: "{{ prefilled_pid }}" })
      });
      const data = await response.json();
      alert(data.message);
    }

    loadData();
  </script>
</body>
</html>
