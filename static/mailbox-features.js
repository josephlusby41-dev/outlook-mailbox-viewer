(() => {
  const field = id => document.getElementById(id);
  const messagePath = id => '/me/messages/' + encodeURIComponent(id);
  const folderPath = id => '/me/mailFolders/' + encodeURIComponent(id);
  const showError = message => {
    if (typeof notice === 'function') notice(message);
    else toast(message, true);
  };

  const modal = document.createElement('dialog');
  modal.className = 'mailbox-feature-dialog';
  modal.setAttribute('aria-label', 'Mailbox actions');
  document.body.append(modal);

  let previewUrl;
  modal.addEventListener('close', () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = undefined;
    modal.replaceChildren();
    modal.classList.remove('feature-wide');
  });

  const style = document.createElement('style');
  style.textContent = `
    .mailbox-feature-dialog{width:min(850px,94vw);max-height:90dvh;padding:20px;border:1px solid #b9cad6;border-radius:14px}
    .mailbox-feature-dialog::backdrop{background:#102a4077}
    .mailbox-feature-dialog h2{margin:0 0 14px;font-size:19px}
    .mailbox-feature-dialog label{display:grid;gap:5px;margin:8px 0}
    .mailbox-feature-dialog input,.mailbox-feature-dialog select,.mailbox-feature-dialog textarea{padding:7px;font:inherit;width:100%}
    .mailbox-feature-dialog input[type=checkbox]{width:auto}
    .mailbox-feature-dialog textarea{min-height:80px}
    .feature-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:10px 0}
    .feature-preview{width:100%;height:min(65vh,720px);border:0;display:block}
    .feature-preview-image{display:block;max-width:100%;max-height:65vh;object-fit:contain}
    .feature-text{white-space:pre-wrap;overflow-wrap:anywhere;max-height:65vh;overflow:auto}
    .feature-error{color:#a1293b;margin:7px 0}
    .feature-file{display:inline-flex;gap:4px;padding:4px;border:1px solid #d7e4ec;border-radius:8px}
    .feature-apps{display:flex;flex-wrap:wrap;gap:5px;align-items:center}
    header .feature-apps .act{border-radius:18px;background:#242b48;color:#f5f5ff;border-color:#505b83}
    header .feature-apps .act[aria-current]{background:#bcebdd;color:#183539;border-color:#bcebdd}
    body>header:has(.feature-apps){background:#20233f;height:auto;min-height:68px;flex-wrap:wrap}
    .feature-wide{width:min(1080px,96vw)}
    .people-tools{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:14px 0}
    .people-tools input[type=search]{flex:1;min-width:180px}
    .people-tools select{width:auto;max-width:240px}
    .people-split{display:grid;grid-template-columns:minmax(230px,1fr) minmax(0,1.5fr);gap:14px}
    .people-list,.people-detail{border:1px solid #dce5ec;border-radius:12px;padding:10px;min-height:180px}
    .people-list{display:grid;align-content:start;gap:4px;max-height:54vh;overflow:auto}
    .people-list button{display:grid;gap:4px;text-align:left;white-space:normal;overflow-wrap:anywhere}
    .people-list button[aria-current]{background:#def1e9;border-color:#76ad9d}
    .people-list small,.rule-row small{display:block;color:#526578;margin-top:3px}
    .people-detail{overflow-wrap:anywhere}
    .rule-group{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 14px;margin:12px 0;border:1px solid #dce5ec;border-radius:10px;padding:12px}
    .rule-general{grid-template-columns:minmax(0,3fr) minmax(85px,1fr) minmax(80px,1fr)}
    .mailbox-feature-dialog .rule-check{display:flex;align-items:center;justify-content:space-between;flex-direction:row}
    .rule-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:12px 0;border-bottom:1px solid #dce5ec}
    .rule-row>div{flex:1}
    @media(max-width:700px){.people-split,.rule-group{grid-template-columns:1fr}.people-list{max-height:35vh}.feature-apps{order:2}.people-tools select{max-width:100%}}
  `;
  document.head.append(style);

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function action(label, run) {
    const control = element('button', label, 'act ghost');
    control.type = 'button';
    control.onclick = async () => {
      control.disabled = true;
      try {
        await run();
      } catch (error) {
        const status = modal.querySelector('.feature-error');
        if (modal.open && status) status.textContent = error.message;
        else showError(error.message);
      } finally {
        control.disabled = false;
      }
    };
    return control;
  }

  function panel(title) {
    modal.classList.remove('feature-wide');
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = undefined;

    const main = element('div');
    const status = element('p', '', 'feature-error');
    status.setAttribute('role', 'alert');
    modal.replaceChildren(
      element('h2', title),
      action('Close', () => modal.close()),
      status,
      main,
    );
    if (!modal.open) modal.showModal();
    return main;
  }

  async function raw(path, method = 'GET', payload) {
    const headers = { 'X-CSRF-Token': CSRF };
    if (payload !== undefined && !(payload instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(payload);
    }

    const response = await fetch(path, { method, headers, body: payload });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.message || `Mailbox request failed (${response.status}).`);
    }
    return response;
  }

  async function send(path, method, data) {
    const response = await raw(path, method, data);
    return response.status === 204 ? {} : response.json();
  }

  function graph(method, path, payload, query) {
    return send('/api/features/graph', 'POST', { method, path, payload, query });
  }

  function saveFile(file, name) {
    const url = URL.createObjectURL(file);
    const link = element('a');
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  async function download(mid, file) {
    const name = file.name || 'Attachment';
    const path = messagePath(mid) + '/attachments/' + encodeURIComponent(file.id) + '/$value';
    const response = await raw('/api/download', 'POST', { path, name });
    saveFile(await response.blob(), name);
  }

  async function preview(mid, file) {
    const main = panel(file.name || 'Attachment preview');
    const info = element('p', 'Loading preview…', 'muted');
    main.append(info, action('Download original', () => download(mid, file)));

    let response;
    try {
      response = await raw('/api/features/preview', 'POST', {
        message: mid,
        attachment: file.id,
      });
    } catch (error) {
      info.remove();
      throw error;
    }
    if (!main.isConnected || !modal.open) return;

    const type = response.headers.get('Content-Type') || '';
    if (type.startsWith('application/json')) {
      const result = await response.json();
      if (!main.isConnected || !modal.open) return;
      info.textContent = file.name?.toLowerCase().endsWith('.docx')
        ? 'Word text preview' : 'Text preview';
      main.append(element('pre', result.text || '(Empty document)', 'feature-text'));
      return;
    }

    const blob = await response.blob();
    if (!main.isConnected || !modal.open) return;

    previewUrl = URL.createObjectURL(blob);
    const pdf = type.startsWith('application/pdf');
    const view = element(
      pdf ? 'iframe' : 'img',
      '',
      pdf ? 'feature-preview' : 'feature-preview-image',
    );
    view.title = file.name || 'Attachment preview';
    if (!pdf) view.alt = view.title;
    view.src = previewUrl;
    info.remove();
    main.append(view);
  }

  async function listFiles(mid, container) {
    try {
      const result = await graph(
        'GET',
        messagePath(mid) + '/attachments',
        undefined,
        { '$select': 'id,name,isInline,contentType,size', '$top': 100 },
      );

      container.replaceChildren();
      container.classList.add('feature-actions');

      for (const file of result.value || []) {
        if (file.isInline) continue;
        const row = element('span', '', 'feature-file');
        row.append(
          action('Preview ' + (file.name || 'attachment'), () => preview(mid, file)),
          action('Download', () => download(mid, file)),
        );
        container.append(row);
      }
    } catch (error) {
      container.textContent = error.message;
    }
  }

  if (typeof showAttachments === 'function') showAttachments = listFiles;
  if (typeof showFiles === 'function') showFiles = listFiles;

  function label(text, control) {
    const node = element('label');
    node.append(text, control);
    return node;
  }

  function options(values, value, caption) {
    const select = element('select');
    for (const item of values) select.add(new Option(caption(item), value(item)));
    return select;
  }

  function folders() {
    if (typeof knownFolders === 'function') return knownFolders();
    if (typeof allFolders === 'function') return allFolders();
    return state.folders || state.roots || [];
  }

  async function reload() {
    modal.close();
    await Promise.all([loadMail(), loadFolders()]);
  }

  function editAttachments(id) {
    const main = panel('Draft attachments');
    const files = element('input');
    files.type = 'file';
    files.multiple = true;

    const attached = element('div', '', 'feature-actions');
    const path = messagePath(id) + '/attachments';

    async function refreshAttachments() {
      const result = await graph('GET', path, undefined, {
        '$select': 'id,name,isInline',
      });
      attached.replaceChildren();

      for (const file of result.value || []) {
        if (file.isInline) continue;
        attached.append(action('Remove ' + file.name, async () => {
          if (!confirm('Remove this attachment from the draft?')) return;
          await graph('DELETE', path + '/' + encodeURIComponent(file.id));
          await refreshAttachments();
        }));
      }
    }

    main.append(
      label('Files smaller than 3 MB each', files),
      action('Add selected files', async () => {
        const selected = [...files.files];
        if (!selected.length) throw new Error('Choose one or more files.');
        if (selected.some(file => !file.size || file.size >= 3_000_000)) {
          throw new Error('Choose nonempty files smaller than 3 MB.');
        }

        let uploaded = 0;
        try {
          for (const file of selected) {
            const form = new FormData();
            form.append('file', file);
            await send('/api/features/attachments/' + encodeURIComponent(id), 'POST', form);
            uploaded++;
          }
        } catch (error) {
          throw new Error(`${uploaded} of ${selected.length} files attached. ${error.message}`);
        } finally {
          files.value = '';
          await refreshAttachments();
        }
      }),
      attached,
    );

    return refreshAttachments();
  }

  function folderTools() {
    const main = panel('Manage folders');
    const available = folders();
    const current = options(available, folder => folder.id, folder => folder.displayName);
    const destination = options(
      [{ id: 'msgfolderroot', displayName: 'Mailbox root' }, ...available],
      folder => folder.id,
      folder => folder.displayName,
    );
    if (available.some(folder => folder.id === state.folder)) current.value = state.folder;

    const name = element('input');
    name.placeholder = 'Folder name';
    function folderName() {
      if (!name.value.trim()) throw new Error('Enter a folder name.');
      return name.value.trim();
    }

    main.append(
      label('Folder', current),
      label('Folder name', name),
      label('Parent or move destination', destination),
    );

    const controls = element('div', '', 'feature-actions');
    controls.append(
      action('Create folder', async () => {
        const path = destination.value === 'msgfolderroot'
          ? '/me/mailFolders' : folderPath(destination.value) + '/childFolders';
        await graph('POST', path, { displayName: folderName() });
        await reload();
      }),
      action('Rename folder', async () => {
        await graph('PATCH', folderPath(current.value), { displayName: folderName() });
        await reload();
      }),
      action('Move folder', async () => {
        await graph('POST', folderPath(current.value) + '/move', {
          destinationId: destination.value,
        });
        state.folder = 'inbox';
        await reload();
      }),
      action('Delete folder', async () => {
        if (!confirm('Delete this folder and its contents?')) return;
        await graph('DELETE', folderPath(current.value));
        state.folder = 'inbox';
        await reload();
      }),
    );
    main.append(controls);
  }

  async function messageTools(id) {
    const path = messagePath(id);
    const item = await graph('GET', path, undefined, {
      '$select': 'subject,importance,categories,internetMessageHeaders',
    });
    const main = panel('Message actions');
    const destination = options(folders(), folder => folder.id, folder => folder.displayName);
    const importance = options(['low', 'normal', 'high'], value => value, value => value);
    importance.value = item.importance || 'normal';

    const categories = element('input');
    categories.value = (item.categories || []).join(', ');
    main.append(
      label('Destination folder', destination),
      label('Importance', importance),
      label('Categories, separated by commas', categories),
    );

    const controls = element('div', '', 'feature-actions');
    controls.append(
      action('Copy to folder', async () => {
        await graph('POST', path + '/copy', { destinationId: destination.value });
        modal.close();
      }),
      action('Move to Inbox', async () => {
        await graph('POST', path + '/move', { destinationId: 'inbox' });
        await reload();
      }),
      action('Move to Junk', async () => {
        await graph('POST', path + '/move', { destinationId: 'junkemail' });
        await reload();
      }),
      action('Save importance and categories', async () => {
        await graph('PATCH', path, {
          importance: importance.value,
          categories: categories.value.split(',').map(value => value.trim()).filter(Boolean),
        });
        modal.close();
      }),
    );

    const headers = element('details');
    headers.append(
      element('summary', 'Internet message headers'),
      element('pre',
        (item.internetMessageHeaders || [])
          .map(header => header.name + ': ' + header.value).join('\n')
          || 'Microsoft did not return headers for this message.',
        'feature-text'),
    );
    main.append(controls, headers);
  }

  const predicateFields = [
    ['fromAddresses','From a specific address','addresses'],
    ['sentToAddresses','Sent to a specific address','addresses'],
    ['senderContains','Sender address includes','words'],
    ['recipientContains','Recipient address includes','words'],
    ['subjectContains','Subject includes','words'],
    ['bodyOrSubjectContains','Subject or body includes','words'],
    ['bodyContains','Message body includes','words'],
    ['headerContains','Message headers include','words'],
    ['categories','Message categories','words'],
    ['hasAttachments','Has an attachment','check'],
    ['sentToMe','I am on the To line','check'],
    ['sentCcMe','I am on the Cc line','check'],
    ['sentToOrCcMe','I am on the To or Cc line','check'],
    ['notSentToMe','I am not a recipient','check'],
    ['sentOnlyToMe','I am the only recipient','check'],
    ['isMeetingRequest','Meeting request','check'],
    ['isAutomaticReply','Automatic reply','check'],
    ['importance','Importance',['low','normal','high']],
    ['sensitivity','Sensitivity',['normal','personal','private','confidential']],
    ['messageActionFlag','Flag for action',['any','followUp','read','reply','review']],
  ];
  const actionFields = [
    ['moveToFolder','Move to folder','folder'],
    ['copyToFolder','Copy to folder','folder'],
    ['assignCategories','Assign categories','words'],
    ['markImportance','Set importance',['low','normal','high']],
    ['markAsRead','Mark as read','check'],
    ['markAsJunk','Mark as junk','check'],
    ['delete','Delete to Deleted Items','check'],
    ['stopProcessingRules','Stop processing more rules','check'],
  ];

  function configurableFields(definitions, source, title, defaultStop = false) {
    const section = element('fieldset');
    section.className = 'rule-group';
    section.append(element('legend', title));
    const controls = [];

    for (const [key, caption, type] of definitions) {
      let input;
      const value = source?.[key];
      if (type === 'folder') {
        const available = [{id:'', displayName:'Choose a folder'}, ...folders()];
        if (value && !available.some(folder => folder.id === value)) {
          available.push({id:value, displayName:'Current folder'});
        }
        input = options(available, folder => folder.id, folder => folder.displayName);
        input.value = value || '';
      } else if (Array.isArray(type)) {
        const choices = ['', ...type];
        if (value && !choices.includes(value)) choices.push(value);
        input = options(choices, entry => entry, entry => entry || 'Any');
        input.value = value || '';
      } else {
        input = element('input');
        if (type === 'check') {
          input.type = 'checkbox';
          input.checked = value === true || (value === undefined && defaultStop && key === 'stopProcessingRules');
        } else {
          input.placeholder = 'Separate multiple values with commas';
          input.value = Array.isArray(value)
            ? value.map(item => typeof item === 'string' ? item : item.emailAddress?.address || '').filter(Boolean).join(', ')
            : '';
        }
      }
      const row = label(caption, input);
      if (type === 'check') row.classList.add('rule-check');
      section.append(row);
      controls.push({key,type,input,original:input.value,checked:input.checked});
    }

    const read = () => {
      const result = Object.fromEntries(Object.entries(source || {}).filter(([key]) => !key.startsWith('@')));
      for (const {key,type,input,original,checked} of controls) {
        if (source && input.value === original && input.checked === checked) continue;
        delete result[key];
        if (type === 'check') {
          if (input.checked) result[key] = true;
          else if (source && source[key] === true) result[key] = false;
        } else if (type === 'words' || type === 'addresses') {
          const terms = input.value.split(',').map(value => value.trim()).filter(Boolean);
          if (type === 'addresses' && terms.some(term => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(term))) {
            throw new Error('Enter complete email addresses separated by commas.');
          }
          if (terms.length) result[key] = type === 'words' ? terms : terms.map(address => ({emailAddress:{address}}));
        } else if (input.value) result[key] = input.value;
      }
      return result;
    };
    return {section, read};
  }

  function editAdvancedRule(rule, nextPriority) {
    const main = panel(rule ? 'Edit inbox rule' : 'Create inbox rule');
    modal.classList.add('feature-wide');
    const name = element('input');
    name.value = rule?.displayName || '';
    name.maxLength = 255;
    const priority = element('input');
    priority.type = 'number';
    priority.min = '1';
    priority.value = rule?.sequence || nextPriority;
    const enabled = element('input');
    enabled.type = 'checkbox';
    enabled.checked = rule?.isEnabled ?? true;
    const conditions = configurableFields(predicateFields, rule?.conditions, 'Match these conditions');
    const exceptions = configurableFields(predicateFields, rule?.exceptions, 'Except when');
    const actions = configurableFields(actionFields, rule?.actions, 'Take these actions', !rule);
    const exceptionsPanel = element('details');
    exceptionsPanel.append(element('summary', 'Exceptions'), exceptions.section);
    const all = element('input');
    all.type = 'checkbox';
    const meaningful = obj => Object.values(obj).some(value =>
      Array.isArray(value) ? value.length > 0 : value !== null && value !== false && value !== '');
    all.checked = Boolean(rule) && !meaningful(rule.conditions || {});
    const footer = element('div', '', 'feature-actions');
    footer.append(action('Back to rules', advancedRules), action('Save rule', async () => {
      if (!name.value.trim()) throw new Error('Enter a rule name.');
      if (!priority.checkValidity() || !Number.isInteger(Number(priority.value)) || Number(priority.value) < 1) {
        throw new Error('Enter a positive whole-number priority.');
      }
      const matches = conditions.read();
      const effects = actions.read();
      if (!meaningful(matches) && !all.checked) throw new Error('Set a condition or choose Apply to every incoming message.');
      if (!meaningful(Object.fromEntries(Object.entries(effects).filter(([key]) => key !== 'stopProcessingRules')))) {
        throw new Error('Choose at least one action.');
      }
      if (effects.delete && (effects.moveToFolder || effects.markAsJunk || effects.permanentDelete)) {
        throw new Error('Choose one action that moves or deletes the message.');
      }
      const payload = {
        displayName:name.value.trim(),
        sequence:Number(priority.value),
        isEnabled:enabled.checked,
        conditions:matches,
        exceptions:exceptions.read(),
        actions:effects,
      };
      await graph(rule ? 'PATCH' : 'POST',
        '/me/mailFolders/inbox/messageRules' + (rule ? '/' + encodeURIComponent(rule.id) : ''), payload);
      await advancedRules();
    }));
    const general = element('div', '', 'rule-group rule-general');
    general.append(label('Name', name), label('Priority', priority), label('Enabled', enabled));
    const allLabel = label('Apply to every incoming message if no condition is set', all);
    allLabel.classList.add('rule-check');
    main.append(general, conditions.section, allLabel, actions.section, exceptionsPanel, footer);
  }

  async function advancedRules() {
    const main = panel('Inbox rules');
    modal.classList.add('feature-wide');
    const status = element('p', 'Loading rules…', 'muted');
    main.append(status);
    const result = await send('/api/rules');
    if (!main.isConnected || !modal.open) return;
    status.remove();
    const entries = result.rules || [];
    const nextPriority = entries.reduce((max, rule) => Math.max(max, Number(rule.sequence) || 0), 0) + 1;
    const search = element('input');
    search.type = 'search';
    search.placeholder = 'Find a rule by name';
    search.setAttribute('aria-label','Find a rule by name');
    const toolbar = element('div', '', 'people-tools');
    toolbar.append(search, action('New rule', () => editAdvancedRule(null, nextPriority)));
    const rows = element('div');
    main.append(toolbar, rows);

    function render() {
      rows.replaceChildren();
      const term = search.value.trim().toLowerCase();
      for (const rule of entries.filter(item => String(item.displayName).toLowerCase().includes(term))) {
        const row = element('div', '', 'rule-row');
        const title = element('div');
        title.append(element('strong', rule.displayName),
          element('small', `Priority ${rule.sequence} · ${rule.isEnabled ? 'Enabled' : 'Disabled'}`, 'muted'));
        row.append(title);
        if (rule.isReadOnly) row.append(element('span', 'Read only', 'muted'));
        else row.append(
          action('Edit', () => editAdvancedRule(rule, nextPriority)),
          action(rule.isEnabled ? 'Disable' : 'Enable', async () => {
            await graph('PATCH', '/me/mailFolders/inbox/messageRules/' + encodeURIComponent(rule.id), {
              isEnabled:!rule.isEnabled,
            });
            await advancedRules();
          }),
          action('Delete', async () => {
            if (!confirm('Delete this inbox rule?')) return;
            await send('/api/rules/' + encodeURIComponent(rule.id), 'DELETE');
            await advancedRules();
          }),
        );
        rows.append(row);
      }
      if (!rows.children.length) rows.append(element('p', term ? 'No matching rules.' : 'No inbox rules yet.', 'muted'));
    }
    search.oninput = render;
    render();
  }

  async function settings() {
    const entry = await graph('GET', '/me/mailboxSettings');
    const automatic = entry.automaticRepliesSetting || {};
    const main = panel('Mailbox settings');

    const zone = element('input');
    zone.value = entry.timeZone || '';
    const enabled = element('input');
    enabled.type = 'checkbox';
    enabled.checked = automatic.status === 'alwaysEnabled';
    const content = element('textarea');
    content.value = automatic.internalReplyMessage || '';

    main.append(
      label('Mailbox time zone', zone),
      label('Enable automatic replies', enabled),
      label('Internal automatic reply', content),
      action('Save settings', async () => {
        const payload = {};
        if (zone.value.trim() && zone.value !== entry.timeZone) {
          payload.timeZone = zone.value.trim();
        }
        if (automatic.status !== 'scheduled' || enabled.checked) {
          payload.automaticRepliesSetting = {
            status: enabled.checked ? 'alwaysEnabled' : 'disabled',
            externalAudience: automatic.externalAudience || 'none',
            internalReplyMessage: content.value,
            externalReplyMessage: automatic.externalReplyMessage || '',
          };
        }
        if (Object.keys(payload).length) await graph('PATCH', '/me/mailboxSettings', payload);
        modal.close();
      }),
    );

    if (automatic.status === 'scheduled') {
      main.append(element(
        'p',
        'A scheduled reply is active. Leave the checkbox off to preserve it.',
        'muted',
      ));
    }
  }

  function contactPath(folder) {
    const ids = folder.ids.map(encodeURIComponent);
    return ids.length ? '/me/contactFolders/' + ids.join('/childFolders/') + '/contacts' : '/me/contacts';
  }

  function exportContacts(contacts) {
    function cell(value) {
      let text = String(value ?? '');
      if (/^\s*[=+@\-]|^[\t\r\n]/u.test(text)) text = "'" + text;
      return '"' + text.replace(/"/g, '""') + '"';
    }
    const header = ['First Name', 'Last Name', 'Display Name', 'E-mail Address',
      'E-mail 2 Address', 'E-mail 3 Address', 'Company', 'Job Title',
      'Mobile Phone', 'Business Phone', 'Business Phone 2', 'Folder'];
    const rows = contacts.map(({ contact, folder }) => [
      contact.givenName, contact.surname, contact.displayName,
      contact.emailAddresses?.[0]?.address, contact.emailAddresses?.[1]?.address,
      contact.emailAddresses?.[2]?.address, contact.companyName, contact.jobTitle,
      contact.mobilePhone, contact.businessPhones?.[0], contact.businessPhones?.[1], folder.label,
    ]);
    const csv = [header, ...rows].map(row => row.map(cell).join(',')).join('\r\n') + '\r\n';
    saveFile(new Blob(['\uFEFF', csv], {type:'text/csv;charset=utf-8'}), 'mailbox-contacts.csv');
  }

  function contactName(contact) {
    return contact.displayName || [contact.givenName, contact.surname].filter(Boolean).join(' ')
      || contact.emailAddresses?.[0]?.address || 'Unnamed contact';
  }

  function contactEditor(folder, contact) {
    const main = panel(contact ? 'Edit contact' : 'New contact');
    const fields = {};
    for (const [key, caption, type] of [
      ['givenName','First name','text'], ['surname','Last name','text'],
      ['companyName','Company','text'], ['jobTitle','Job title','text'],
      ['mobilePhone','Mobile phone','tel'], ['email','Email address','email'],
    ]) {
      const input = element('input');
      input.type = type;
      input.value = key === 'email' ? (contact?.emailAddresses?.[0]?.address || '') : (contact?.[key] || '');
      fields[key] = input;
      main.append(label(caption, input));
    }
    main.append(action('Back to People', people), action('Save contact', async () => {
      if (!fields.email.checkValidity()) throw new Error('Enter a valid email address.');
      const {email, ...names} = fields;
      const payload = Object.fromEntries(Object.entries(names).map(([key,input]) => [key,input.value.trim()]));
      if (!payload.givenName && !payload.surname && !email.value.trim()) {
        throw new Error('Enter a name or email address.');
      }
      if (!contact || email.value.trim() !== (contact.emailAddresses?.[0]?.address || '')) {
        const other = contact?.emailAddresses?.slice(1) || [];
        payload.emailAddresses = email.value.trim() ? [{address:email.value.trim()}, ...other] : other;
      }
      const path = contactPath(folder);
      await graph(contact ? 'PATCH' : 'POST', contact ? path + '/' + encodeURIComponent(contact.id) : path, payload);
      await people();
    }));
  }

  function outlookPeopleExport() {
    const link = element('a', 'Open Outlook to download expanded people data');
    link.href = 'https://outlook.cloud.microsoft/mail/options/general/export';
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
  }

  async function suggestedPeople() {
    const main = panel('Suggested people');
    modal.classList.add('feature-wide');
    const form = element('form', '', 'people-tools');
    const search = element('input');
    search.type = 'search';
    search.maxLength = 120;
    search.placeholder = 'Search names or email addresses';
    search.setAttribute('aria-label', 'Search suggested people');
    const submit = element('button', 'Search', 'act');
    submit.type = 'submit';
    form.append(search, submit, action('Saved contacts', people));

    const status = element('p', 'Loading suggestions…', 'muted');
    status.setAttribute('role', 'status');
    const list = element('div', '', 'people-list');
    const connect = element('a', 'Sign in with Microsoft to allow People access');
    connect.href = '/auth/microsoft?area=suggestions';
    connect.hidden = true;
    const more = action('Load more', () => load(true));
    more.hidden = true;
    main.append(form, status, connect, list, more, element('p', '', 'feature-actions'));
    main.lastElementChild.append(outlookPeopleExport());

    const seen = new Set();
    let cursor;
    let term = '';
    let version = 0;
    async function load(append = false) {
      if (append && !cursor) return;
      const serial = ++version;
      if (!append) {
        term = search.value.trim();
        cursor = null;
        seen.clear();
        list.replaceChildren();
      }
      const params = new URLSearchParams({search:term});
      if (cursor) params.set('cursor', cursor);
      more.hidden = true;
      connect.hidden = true;
      status.textContent = 'Loading suggestions…';
      try {
        const page = await send('/api/people/suggestions?' + params);
        if (!main.isConnected || !modal.open || serial !== version) return;
        for (const person of page.items || []) {
          const address = (person.scoredEmailAddresses || []).find(entry => entry.address)?.address;
          if (!address || seen.has(address.toLowerCase())) continue;
          seen.add(address.toLowerCase());
          const row = action(person.displayName || address, () => {
            modal.close();
            if (typeof openCompose === 'function') openCompose();
            else compose();
            const recipient = field('cTo') || field('to');
            if (recipient) recipient.value = address;
          });
          row.append(element('small', address));
          list.append(row);
        }
        cursor = page.cursor;
        more.hidden = !cursor;
        status.textContent = seen.size
          ? `${seen.size} Microsoft suggestions shown. Select a person to compose a message.`
          : 'Microsoft returned no suggestions for this view.';
      } catch (error) {
        if (!main.isConnected || !modal.open || serial !== version) return;
        status.textContent = error.message;
        more.hidden = !cursor;
        try {
          const account = await send('/api/session');
          if (main.isConnected && serial === version) connect.hidden = !account.oauth;
        } catch (_) {}
      }
    }
    form.onsubmit = event => {
      event.preventDefault();
      load();
    };
    await load();
  }

  async function people() {
    const main = panel('Saved contacts');
    modal.classList.add('feature-wide');
    const defaultFolder = { ids: [], label: 'Contacts' };
    const contactFolders = [defaultFolder];
    const contacts = new Map();
    let selected = null;
    let complete = false;
    let renderFrame = 0;

    const filters = element('div', '', 'people-tools');
    const scope = element('select');
    scope.setAttribute('aria-label', 'Contact folder');
    scope.add(new Option('All contacts', 'all'));
    scope.add(new Option('Contacts', '0'));
    const search = element('input');
    search.type = 'search';
    search.placeholder = 'Search names, addresses, or companies';
    search.setAttribute('aria-label', 'Search contacts');
    const exportButton = action('Export CSV', () => exportContacts(byFolder()));
    const newButton = action('New contact', () => contactEditor(contactFolders[Number(scope.value)] || defaultFolder));
    const status = element('p', 'Loading saved contacts…', 'muted');
    status.setAttribute('role', 'status');
    const layout = element('div', '', 'people-split');
    const list = element('div', '', 'people-list');
    const detail = element('div', '', 'people-detail');
    layout.append(list, detail);
    filters.append(search, scope, newButton, exportButton, action('Refresh', people),
      action('Suggested people', suggestedPeople));
    main.append(filters, status, layout);

    const current = () => main.isConnected && modal.open;
    const byFolder = () => Array.from(contacts.values()).filter(item =>
      scope.value === 'all' || item.folder === contactFolders[Number(scope.value)]);

    function render() {
      if (!current()) return;
      const records = byFolder();
      const term = search.value.trim().toLowerCase();
      const visible = records.filter(({contact}) => [
        contactName(contact), contact.companyName, contact.jobTitle, contact.mobilePhone,
        ...(contact.emailAddresses || []).map(email => email.address),
        ...(contact.businessPhones || []),
      ].some(value => String(value || '').toLowerCase().includes(term)));
      visible.sort((a,b) => contactName(a.contact).localeCompare(contactName(b.contact)));
      list.replaceChildren();
      status.textContent = complete
        ? `${visible.length} shown · ${records.length} in the selected scope`
        : `Loading saved contacts… ${contacts.size} found`;
      exportButton.disabled = !complete || !records.length;
      if (selected && !visible.includes(selected)) selected = null;
      for (const record of visible) {
        const control = action(contactName(record.contact), () => {
          selected = record;
          list.querySelector('[aria-current]')?.removeAttribute('aria-current');
          control.setAttribute('aria-current','true');
          renderDetail();
        });
        if (selected === record) control.setAttribute('aria-current', 'true');
        const address = element('small', record.contact.emailAddresses?.[0]?.address || record.folder.label);
        control.append(address);
        list.append(control);
      }
      if (!visible.length && complete) list.append(element('p', 'No contacts found.', 'muted'));
      renderDetail();
    }

    function renderDetail() {
      detail.replaceChildren();
      if (!selected) {
        detail.append(element('p', 'Select a contact to see their details.', 'muted'));
        return;
      }
      const {contact, folder} = selected;
      detail.append(element('h3', contactName(contact)), element('p', folder.label, 'muted'));
      const info = [contact.jobTitle, contact.companyName, contact.mobilePhone, ...(contact.businessPhones || [])];
      for (const value of info.filter(Boolean)) detail.append(element('p', value));
      for (const email of contact.emailAddresses || []) {
        if (!email.address) continue;
        detail.append(action(email.address, () => {
          modal.close();
          if (typeof openCompose === 'function') openCompose();
          else compose();
          const fieldTo = field('cTo') || field('to');
          if (fieldTo) fieldTo.value = email.address;
        }));
      }
      const buttons = element('div', '', 'feature-actions');
      buttons.append(action('Edit', () => contactEditor(folder, contact)), action('Delete', async () => {
        if (!confirm('Delete this saved contact?')) return;
        await graph('DELETE', contactPath(folder) + '/' + encodeURIComponent(contact.id));
        await people();
      }));
      detail.append(buttons);
    }

    function scheduleRender() {
      if (!renderFrame) renderFrame = requestAnimationFrame(() => {
        renderFrame = 0;
        render();
      });
    }
    search.oninput = render;
    scope.onchange = render;
    render();

    async function pages(kind, folder, consume) {
      let cursor = null;
      do {
        if (!current()) return;
        const params = new URLSearchParams({kind});
        for (const id of folder.ids) params.append('parent', id);
        if (cursor) params.set('cursor', cursor);
        const data = await send('/api/people?' + params);
        if (!current()) return;
        for (const item of data.items || []) consume(item);
        cursor = data.cursor;
        scheduleRender();
      } while (cursor);
    }

    const discovered = new Set();
    try {
      for (let index = 0; index < contactFolders.length && current(); index++) {
        const folder = contactFolders[index];
        await pages('contacts', folder, contact => {
          if (contact.id && !contacts.has(contact.id)) contacts.set(contact.id, {contact, folder});
        });
        await pages('folders', folder, child => {
          if (!child.id || discovered.has(child.id)) return;
          discovered.add(child.id);
          const name = child.displayName || 'Unnamed folder';
          const childFolder = {ids:[...folder.ids, child.id], label:folder.ids.length ? folder.label + ' / ' + name : name};
          scope.add(new Option(childFolder.label, String(contactFolders.length)));
          contactFolders.push(childFolder);
        });
      }
      if (!current()) return;
      complete = true;
      render();
    } catch (error) {
      if (!current()) return;
      cancelAnimationFrame(renderFrame);
      render();
      status.textContent = `Loaded ${contacts.size} contacts before Microsoft stopped the scan. ${error.message}`;
      const consent = element('a', 'Sign in with Microsoft to grant app permissions');
      consent.href = '/auth/microsoft?apps=1';
      try {
        const session = await send('/api/session');
        if (session.oauth && current()) main.append(consent);
      } catch (_) {}
    }
  }

  async function tasks() {
    const data = await graph('GET', '/me/todo/lists');
    const view = panel('Microsoft To Do lists');
    for (const list of data.value || []) {
      view.append(action(list.displayName, () => records('tasks', list)));
    }
    if (!view.children.length) view.textContent = 'No task lists.';
  }

  const recordViews = {
    calendar: {
      title: 'Calendar · next 30 days',
      list: '/me/calendarView', write: '/me/events', text: 'subject',
      fields: [['subject','Title'], ['start','Start (UTC)','datetime-local'], ['end','End (UTC)','datetime-local']],
    },
    tasks: {
      title: 'Tasks', text: 'title',
      fields: [['title','Task'], ['dueDateTime','Due (UTC)','datetime-local']],
    },
  };

  async function records(kind, list) {
    const view = {...recordViews[kind]};
    let query = {'$top':50};
    if (kind === 'calendar') {
      query = {...query, startDateTime:new Date().toISOString(),
        endDateTime:new Date(Date.now() + 30 * 86400000).toISOString()};
    }
    if (kind === 'tasks') {
      view.list = view.write = '/me/todo/lists/' + encodeURIComponent(list.id) + '/tasks';
      view.title = list.displayName || view.title;
    }
    const result = await graph('GET', view.list, undefined, query);
    const main = panel(view.title);
    main.append(action('New', () => editRecord(kind, list, view)));
    for (const record of result.value || []) {
      const description = [record[view.text], record.start?.dateTime, record.emailAddresses?.[0]?.address,
        record.status === 'completed' ? 'Completed' : ''].filter(Boolean).join(' · ');
      const path = view.write + '/' + encodeURIComponent(record.id);
      const row = element('div', '', 'feature-actions');
      row.append(element('strong', description || '(Untitled)'),
        action('Edit', () => editRecord(kind, list, view, record)),
        action('Delete', async () => {
          if (!confirm('Delete this item?')) return;
          await graph('DELETE', path);
          await records(kind, list);
        }));
      if (kind === 'tasks' && record.status !== 'completed') row.append(action('Complete', async () => {
        await graph('PATCH', path, {status:'completed'});
        await records(kind, list);
      }));
      main.append(row);
    }
    if (result['@odata.nextLink']) main.append(element('p', 'Showing the first page.', 'muted'));
  }

  function editRecord(kind, list, view, record) {
    const main = panel(record ? 'Edit item' : 'New item');
    const fields = {};
    for (const [key, caption, type = 'text'] of view.fields) {
      const input = element('input');
      input.type = type;
      input.value = type === 'datetime-local' ? (record?.[key]?.dateTime || '').slice(0,16) : record?.[key] || '';
      fields[key] = input;
      main.append(label(caption, input));
    }
    main.append(action('Save', async () => {
      const payload = {};
      for (const [key, input] of Object.entries(fields)) {
        const value = input.value.trim();
        if (!input.checkValidity()) throw new Error('Check the value in ' + input.parentNode.textContent + '.');
        if (input.type === 'datetime-local') {
          if (value) payload[key] = {dateTime:value + ':00', timeZone:'UTC'};
          else if (key === 'dueDateTime' && record?.dueDateTime) payload[key] = null;
        } else payload[key] = value;
      }
      if (kind === 'calendar' && (!payload.subject || !payload.start || !payload.end || payload.start.dateTime >= payload.end.dateTime)) {
        throw new Error('Enter a title, start, and later end time.');
      }
      if (kind === 'tasks' && !payload.title) throw new Error('Enter a task name.');
      await graph(record ? 'PATCH' : 'POST',
        record ? view.write + '/' + encodeURIComponent(record.id) : view.write, payload);
      await records(kind, list);
    }));
  }

  const originalOpen = openMessage;
  openMessage = async function (id) {
    await originalOpen(id);
    const reader = field('reader');
    if ((state.openId || state.open) !== id || !reader.querySelector('h2')) return;

    if (!reader.querySelector('[data-feature-actions]')) {
      const controls = element('div', '', 'feature-actions');
      controls.dataset.featureActions = 'true';
      controls.append(action('More message actions', () => messageTools(id)));

      if (reader.querySelector('[data-compose="draft"]')
        || [...reader.querySelectorAll('button')].some(button => button.textContent === 'Edit draft')) {
        controls.append(action('Manage draft attachments', () => editAttachments(id)));
      }
      reader.append(controls);
    }
  };

  async function settingsHub() {
    const main = panel('Settings');
    const navigation = element('nav', '', 'feature-apps');
    navigation.setAttribute('aria-label', 'Settings sections');
    navigation.append(action('Inbox rules', advancedRules), action('Mailbox settings', settings),
      action('Manage folders', folderTools));
    main.append(navigation);
    const connection = await send('/api/session');
    if (connection.oauth && main.isConnected) {
      const grant = element('a', 'Connect People, Calendar, and Tasks with Microsoft');
      grant.href = '/auth/microsoft?apps=1';
      main.append(grant);
    }
  }

  const header = document.querySelector('body > header');
  if (header) {
    const apps = element('nav', '', 'feature-apps');
    apps.setAttribute('aria-label','Mail Console apps');
    const mail = action('Mail', () => field('search')?.focus());
    mail.setAttribute('aria-current','page');
    apps.append(mail, action('People', suggestedPeople), action('Calendar', () => records('calendar')),
      action('Tasks', tasks), action('Settings', settingsHub));
    header.insertBefore(apps, header.querySelector('#who, #account'));
    const existingRules = [...header.querySelectorAll('button')].find(control => control.textContent.trim() === 'Inbox rules');
    if (existingRules) {
      existingRules.onclick = action('Inbox rules', advancedRules).onclick;
    }
  }
})();
