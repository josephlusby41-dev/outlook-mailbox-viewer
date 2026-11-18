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

  async function ruleSettings() {
    const data = await send('/api/rules');
    const main = panel('Rule priority and status');

    for (const rule of data.rules || []) {
      const row = element('div', '', 'feature-actions');
      const enabled = element('input');
      enabled.type = 'checkbox';
      enabled.checked = Boolean(rule.isEnabled);

      const sequence = element('input');
      sequence.type = 'number';
      sequence.min = '1';
      sequence.value = rule.sequence;
      sequence.style.width = '6em';

      const stop = element('input');
      stop.type = 'checkbox';
      stop.checked = Boolean(rule.actions?.stopProcessingRules);

      row.append(
        element('strong', rule.displayName),
        label('Enabled', enabled),
        label('Priority', sequence),
        label('Stop after this rule', stop),
      );

      if (rule.isReadOnly) {
        row.append(element('span', 'Read only', 'muted'));
      } else {
        row.append(action('Save', async () => {
          const priority = Number(sequence.value);
          if (!Number.isInteger(priority) || priority < 1) {
            throw new Error('Enter a whole-number priority.');
          }
          const payload = { sequence: priority, isEnabled: enabled.checked };
          if (stop.checked !== Boolean(rule.actions?.stopProcessingRules)) {
            if (!rule.actions) throw new Error('Microsoft did not return the existing actions.');
            payload.actions = { ...rule.actions, stopProcessingRules: stop.checked };
          }
          await graph(
            'PATCH',
            '/me/mailFolders/inbox/messageRules/' + encodeURIComponent(rule.id),
            payload,
          );
          await ruleSettings();
        }));
      }
      main.append(row);
    }
    if (!main.children.length) main.append(element('p', 'No inbox rules.'));
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

  const recordViews = {
    calendar: {
      title: 'Calendar · next 30 days',
      list: '/me/calendarView',
      write: '/me/events',
      text: 'subject',
      fields: [
        ['subject', 'Title'],
        ['start', 'Start (UTC)', 'datetime-local'],
        ['end', 'End (UTC)', 'datetime-local'],
      ],
    },
    contacts: {
      title: 'Contacts',
      list: '/me/contacts',
      write: '/me/contacts',
      text: 'displayName',
      fields: [
        ['givenName', 'First name'],
        ['surname', 'Last name'],
        ['email', 'Email address', 'email'],
      ],
    },
    tasks: {
      title: 'Tasks',
      text: 'title',
      fields: [
        ['title', 'Task'],
        ['dueDateTime', 'Due (UTC)', 'datetime-local'],
      ],
    },
  };

  async function records(kind, list) {
    const view = { ...recordViews[kind] };
    let query = { '$top': 50 };

    if (kind === 'calendar') {
      query = {
        ...query,
        startDateTime: new Date().toISOString(),
        endDateTime: new Date(Date.now() + 30 * 86400000).toISOString(),
      };
    }
    if (kind === 'tasks') {
      view.list = view.write = '/me/todo/lists/' + encodeURIComponent(list.id) + '/tasks';
      view.title = list.displayName || view.title;
    }

    const result = await graph('GET', view.list, undefined, query);
    const main = panel(view.title);
    main.append(action('New', () => editRecord(kind, list, view)));

    for (const record of result.value || []) {
      const description = [
        record[view.text],
        record.start?.dateTime,
        record.emailAddresses?.[0]?.address,
        record.status === 'completed' ? 'Completed' : '',
      ].filter(Boolean).join(' · ');

      const path = view.write + '/' + encodeURIComponent(record.id);
      const row = element('div', '', 'feature-actions');
      row.append(
        element('strong', description || '(Untitled)'),
        action('Edit', () => editRecord(kind, list, view, record)),
        action('Delete', async () => {
          if (!confirm('Delete this item?')) return;
          await graph('DELETE', path);
          await records(kind, list);
        }),
      );

      if (kind === 'tasks' && record.status !== 'completed') {
        row.append(action('Complete', async () => {
          await graph('PATCH', path, { status: 'completed' });
          await records(kind, list);
        }));
      }
      main.append(row);
    }

    if (result['@odata.nextLink']) {
      main.append(element('p', 'Showing the first page.', 'muted'));
    }
  }

  function editRecord(kind, list, view, record) {
    const main = panel(record ? 'Edit item' : 'New item');
    const fields = {};

    for (const [key, caption, type = 'text'] of view.fields) {
      const input = element('input');
      input.type = type;
      if (key === 'email') input.value = record?.emailAddresses?.[0]?.address || '';
      else if (type === 'datetime-local') input.value = (record?.[key]?.dateTime || '').slice(0, 16);
      else input.value = record?.[key] || '';
      fields[key] = input;
      main.append(label(caption, input));
    }

    main.append(action('Save', async () => {
      const payload = {};

      for (const [key, input] of Object.entries(fields)) {
        const value = input.value.trim();
        if (!input.checkValidity()) {
          throw new Error('Check the value in ' + input.parentNode.textContent + '.');
        }
        if (key === 'email') {
          const other = record?.emailAddresses?.slice(1) || [];
          payload.emailAddresses = value ? [{ address: value }, ...other] : other;
        } else if (input.type === 'datetime-local') {
          if (value) payload[key] = { dateTime: value + ':00', timeZone: 'UTC' };
          else if (key === 'dueDateTime' && record?.dueDateTime) payload[key] = null;
        } else {
          payload[key] = value;
        }
      }

      if (kind === 'calendar' && (
        !payload.subject || !payload.start || !payload.end
        || payload.start.dateTime >= payload.end.dateTime
      )) {
        throw new Error('Enter a title, start, and later end time.');
      }
      if (kind === 'contacts' && !payload.givenName && !payload.surname) {
        throw new Error('Enter a contact name.');
      }
      if (kind === 'tasks' && !payload.title) throw new Error('Enter a task name.');

      await graph(
        record ? 'PATCH' : 'POST',
        record ? view.write + '/' + encodeURIComponent(record.id) : view.write,
        payload,
      );
      await records(kind, list);
    }));
  }

  function tools() {
    const main = panel('Mailbox tools');
    main.append(
      action('Calendar', () => records('calendar')),
      action('Contacts', () => records('contacts')),
      action('Microsoft To Do', async () => {
        const data = await graph('GET', '/me/todo/lists');
        const view = panel('Microsoft To Do lists');

        for (const list of data.value || []) {
          view.append(action(list.displayName, () => records('tasks', list)));
        }
        if (!view.children.length) view.textContent = 'No task lists.';
      }),
    );
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

  const header = document.querySelector('body > header');
  if (header) {
    header.append(
      action('Manage folders', folderTools),
      action('Mailbox settings', settings),
      action('Rule priority', ruleSettings),
      action('More apps', tools),
    );
  }
})();
