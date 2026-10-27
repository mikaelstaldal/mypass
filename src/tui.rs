use std::io::{self};
use std::path::Path;

use anyhow::Context;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use zeroize::{Zeroize, ZeroizeOnDrop};

use mypass::{Params, PasswordEntry, Secret};

pub fn run(file: &Path, params: &Params, clear_timeout: u64) -> anyhow::Result<()> {
    let passphrase = super::obtain_passphrase(false, false)?;
    let entries = mypass::list(file, &passphrase)?;
    drop(passphrase);

    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::new(entries, clear_timeout);
    loop {
        terminal.terminal.draw(|frame| app.draw(frame))?;
        if let Event::Key(key) = event::read().context("cannot read terminal input")? {
            if key.kind == KeyEventKind::Press && app.handle_key(key) {
                break;
            }
        }
    }
    terminal.leave()?;

    let result = match app.exit {
        Exit::Save => save_with_retry(file, params, &app.entries),
        Exit::Discard => {
            eprintln!("Changes discarded.");
            Ok(())
        }
        Exit::Clean => Ok(()),
        Exit::Running => unreachable!(),
    };
    if let Some(mut copied) = app.copied_password.take() {
        super::announce_copied("Password", clear_timeout);
        super::wait_and_clear(&mut copied, clear_timeout);
    }
    result
}

fn save_with_retry(file: &Path, params: &Params, entries: &[PasswordEntry]) -> anyhow::Result<()> {
    loop {
        let result = super::obtain_passphrase(false, false).and_then(|passphrase| {
            mypass::replace_all(file, &passphrase, entries, params).map_err(Into::into)
        });
        match result {
            Ok(()) => {
                println!("Saved {} entries to {}.", entries.len(), file.display());
                return Ok(());
            }
            Err(err) => {
                eprintln!("Could not save the vault: {err:#}");
                if !confirm_retry()? {
                    eprintln!("Changes discarded.");
                    return Ok(());
                }
            }
        }
    }
}

fn confirm_retry() -> anyhow::Result<bool> {
    use std::io::Write;
    eprint!("Retry saving? [Y/n] ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(!matches!(line.trim(), "n" | "N" | "no" | "No"))
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    active: bool,
}

impl TerminalGuard {
    fn enter() -> anyhow::Result<Self> {
        enable_raw_mode().context("cannot enable terminal raw mode")?;
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(err).context("cannot enter alternate screen");
        }
        let terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => terminal,
            Err(err) => {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
                return Err(err).context("cannot initialize terminal");
            }
        };
        Ok(Self {
            terminal,
            active: true,
        })
    }

    fn leave(&mut self) -> anyhow::Result<()> {
        if self.active {
            disable_raw_mode().context("cannot disable terminal raw mode")?;
            execute!(self.terminal.backend_mut(), LeaveAlternateScreen)
                .context("cannot leave alternate screen")?;
            self.terminal.show_cursor()?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Exit {
    Running,
    Clean,
    Save,
    Discard,
}

enum Mode {
    Browse,
    Search,
    Edit(Form),
    ConfirmDelete,
    ConfirmExit,
}

struct App {
    entries: Vec<PasswordEntry>,
    clear_timeout: u64,
    selected: usize,
    query: String,
    dirty: bool,
    mode: Mode,
    message: Option<String>,
    copied_password: Option<super::CopiedPassword>,
    exit: Exit,
}

impl App {
    fn new(mut entries: Vec<PasswordEntry>, clear_timeout: u64) -> Self {
        entries.sort_by_key(|e| e.name.to_lowercase());
        Self {
            entries,
            clear_timeout,
            selected: 0,
            query: String::new(),
            dirty: false,
            mode: Mode::Browse,
            message: None,
            copied_password: None,
            exit: Exit::Running,
        }
    }

    fn visible_indices(&self) -> Vec<usize> {
        let query = self.query.to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                [
                    &entry.name[..],
                    &entry.username[..],
                    entry.url.as_deref().unwrap_or_default(),
                    entry.realm.as_deref().unwrap_or_default(),
                ]
                .iter()
                .any(|value| value.to_lowercase().contains(&query))
                .then_some(index)
            })
            .collect()
    }

    fn selected_index(&self) -> Option<usize> {
        self.visible_indices().get(self.selected).copied()
    }

    fn clear_search(&mut self) {
        let selected = self.selected_index().unwrap_or(0);
        self.query.clear();
        self.selected = selected;
    }

    fn draw(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(2)])
            .split(frame.area());
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(chunks[0]);

        let visible = self.visible_indices();
        let items = visible
            .iter()
            .map(|&index| ListItem::new(super::sanitize(&self.entries[index].name)));
        let mut state = ListState::default();
        if !visible.is_empty() {
            state.select(Some(self.selected));
        }
        let title = format!(
            " Entries ({}/{}){} ",
            visible.len(),
            self.entries.len(),
            if self.dirty { " *" } else { "" }
        );
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::default().title(title).borders(Borders::ALL))
                .highlight_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("> "),
            body[0],
            &mut state,
        );

        let detail = self
            .selected_index()
            .map(|index| &self.entries[index])
            .map(|entry| {
                vec![
                    Line::from(vec![
                        Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(super::sanitize(&entry.name)),
                    ]),
                    Line::from(vec![
                        Span::styled("Username: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(super::sanitize(&entry.username)),
                    ]),
                    Line::from(vec![
                        Span::styled("Password: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw("••••••••"),
                    ]),
                    Line::from(vec![
                        Span::styled("URL: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(
                            entry
                                .url
                                .as_deref()
                                .map(super::sanitize)
                                .unwrap_or_default(),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Realm: ", Style::default().add_modifier(Modifier::BOLD)),
                        Span::raw(
                            entry
                                .realm
                                .as_deref()
                                .map(super::sanitize)
                                .unwrap_or_default(),
                        ),
                    ]),
                ]
            })
            .unwrap_or_else(|| {
                vec![Line::from(if self.entries.is_empty() {
                    "The vault is empty. Press n or Insert to create an entry."
                } else {
                    "No matching entries. Press / to change the search or Esc to clear it."
                })]
            });
        frame.render_widget(
            Paragraph::new(detail)
                .block(Block::default().title(" Details ").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            body[1],
        );

        let search_help = format!("/{}  Enter browse  Esc clear", super::sanitize(&self.query));
        let filtered_help = format!("Search: {}  / edit search  Esc clear  ↑/↓ move  c copy  n new  e edit  d delete  q quit", super::sanitize(&self.query));
        let help = self
            .message
            .as_deref()
            .unwrap_or(if matches!(self.mode, Mode::Search) {
                &search_help
            } else if !self.query.is_empty() {
                &filtered_help
            } else {
                "↑/↓ move  / search  c copy  n/Ins new  e/Enter edit  d/Del delete  q/Esc quit"
            });
        frame.render_widget(
            Paragraph::new(help)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(if self.message.is_some() {
                    Color::Yellow
                } else {
                    Color::Gray
                })),
            chunks[1],
        );

        match &self.mode {
            Mode::Edit(form) => draw_form(frame, form),
            Mode::ConfirmDelete => draw_popup(
                frame,
                " Delete entry? ",
                "Delete selected entry?  y yes  n/Esc no",
                54,
                5,
            ),
            Mode::ConfirmExit => draw_popup(
                frame,
                " Unsaved changes ",
                "s save  d discard  Esc keep editing",
                52,
                5,
            ),
            Mode::Browse | Mode::Search => {}
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        self.message = None;
        let mode = std::mem::replace(&mut self.mode, Mode::Browse);
        self.mode = match mode {
            Mode::Browse => {
                self.handle_browse(key);
                std::mem::replace(&mut self.mode, Mode::Browse)
            }
            Mode::Search => {
                match key.code {
                    KeyCode::Enter => self.mode = Mode::Browse,
                    KeyCode::Esc => {
                        self.clear_search();
                        self.mode = Mode::Browse;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.handle_browse(key);
                    }
                    KeyCode::Backspace => {
                        self.query.pop();
                        self.selected = 0;
                        self.mode = Mode::Search;
                    }
                    KeyCode::Char(c)
                        if !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                            && !c.is_control() =>
                    {
                        self.query.push(c);
                        self.selected = 0;
                        self.mode = Mode::Search;
                    }
                    _ => self.mode = Mode::Search,
                }
                std::mem::replace(&mut self.mode, Mode::Browse)
            }
            Mode::ConfirmDelete => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(index) = self.selected_index() {
                        self.entries.remove(index);
                    }
                    self.selected = self
                        .selected
                        .min(self.visible_indices().len().saturating_sub(1));
                    self.dirty = true;
                    Mode::Browse
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => Mode::Browse,
                _ => Mode::ConfirmDelete,
            },
            Mode::ConfirmExit => match key.code {
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.exit = Exit::Save;
                    return true;
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    self.exit = Exit::Discard;
                    return true;
                }
                KeyCode::Esc => Mode::Browse,
                _ => Mode::ConfirmExit,
            },
            Mode::Edit(mut form) => match form.handle_key(key, &self.entries) {
                FormResult::Continue => Mode::Edit(form),
                FormResult::Cancel => Mode::Browse,
                FormResult::Save(entry) => {
                    if let Some(index) = form.editing {
                        self.entries[index] = entry;
                        let name = self.entries[index].name.clone();
                        self.entries.sort_by_key(|e| e.name.to_lowercase());
                        self.selected = self
                            .entries
                            .iter()
                            .position(|e| e.name == name)
                            .unwrap_or(0);
                    } else {
                        self.entries.push(entry);
                        self.entries.sort_by_key(|e| e.name.to_lowercase());
                        self.selected = self
                            .entries
                            .iter()
                            .position(|e| e.name == form.name)
                            .unwrap_or(0);
                    }
                    let visible = self.visible_indices();
                    let position = visible.iter().position(|&index| index == self.selected);
                    self.message = Some(if position.is_some() {
                        "Entry saved".into()
                    } else {
                        "Entry saved (hidden by search; press Esc to clear)".into()
                    });
                    self.selected = position.unwrap_or(0);
                    self.dirty = true;
                    Mode::Browse
                }
                FormResult::Error(message) => {
                    form.error = Some(message);
                    Mode::Edit(form)
                }
            },
        };
        self.exit != Exit::Running
    }

    fn handle_browse(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.visible_indices().len() {
                    self.selected += 1;
                }
            }
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = self.visible_indices().len().saturating_sub(1),
            KeyCode::Char('/') => self.mode = Mode::Search,
            KeyCode::Esc if !self.query.is_empty() => {
                self.clear_search();
            }
            KeyCode::Char('n') | KeyCode::Insert => self.mode = Mode::Edit(Form::new()),
            KeyCode::Char('e') | KeyCode::Enter if self.selected_index().is_some() => {
                let index = self.selected_index().unwrap();
                self.mode = Mode::Edit(Form::edit(index, &self.entries[index]))
            }
            KeyCode::Char('d') | KeyCode::Delete if self.selected_index().is_some() => {
                self.mode = Mode::ConfirmDelete
            }
            KeyCode::Char('c')
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && self.selected_index().is_some() =>
            {
                match super::copy_to_clipboard(
                    self.entries[self.selected_index().unwrap()]
                        .password
                        .expose(),
                    self.clear_timeout,
                ) {
                    Ok(secret) => {
                        self.copied_password = Some(secret);
                        self.message = Some("Password copied to clipboard".to_string());
                    }
                    Err(err) => self.message = Some(format!("Clipboard error: {err}")),
                }
            }
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.dirty {
                    self.mode = Mode::ConfirmExit;
                } else {
                    self.exit = Exit::Clean;
                }
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.dirty {
                    self.mode = Mode::ConfirmExit;
                } else {
                    self.exit = Exit::Clean;
                }
            }
            _ => {}
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Form {
    editing: Option<usize>,
    active: usize,
    cursor: usize,
    name: String,
    username: String,
    password: String,
    url: String,
    realm: String,
    #[zeroize(skip)]
    error: Option<String>,
}

enum FormResult {
    Continue,
    Cancel,
    Save(PasswordEntry),
    Error(String),
}

impl Form {
    fn new() -> Self {
        Self {
            editing: None,
            active: 0,
            cursor: 0,
            name: String::new(),
            username: String::new(),
            password: String::with_capacity(64),
            url: String::new(),
            realm: String::new(),
            error: None,
        }
    }
    fn edit(index: usize, entry: &PasswordEntry) -> Self {
        let mut password = String::with_capacity(entry.password.expose().len().max(64));
        password.push_str(entry.password.expose());
        Self {
            editing: Some(index),
            active: 0,
            cursor: entry.name.chars().count(),
            name: entry.name.clone(),
            username: entry.username.clone(),
            password,
            url: entry.url.clone().unwrap_or_default(),
            realm: entry.realm.clone().unwrap_or_default(),
            error: None,
        }
    }
    fn fields(&self) -> [&str; 5] {
        [
            &self.name,
            &self.username,
            &self.password,
            &self.url,
            &self.realm,
        ]
    }
    fn active_mut(&mut self) -> &mut String {
        match self.active {
            0 => &mut self.name,
            1 => &mut self.username,
            2 => &mut self.password,
            3 => &mut self.url,
            _ => &mut self.realm,
        }
    }
    fn active_value(&self) -> &str {
        self.fields()[self.active]
    }
    fn move_field(&mut self, delta: usize) {
        self.active = (self.active + delta) % 5;
        self.cursor = self.active_value().chars().count();
    }
    fn byte_at(value: &str, char_index: usize) -> usize {
        value
            .char_indices()
            .nth(char_index)
            .map_or(value.len(), |(index, _)| index)
    }
    fn handle_key(&mut self, key: KeyEvent, entries: &[PasswordEntry]) -> FormResult {
        self.error = None;
        match key.code {
            KeyCode::Esc => return FormResult::Cancel,
            KeyCode::Tab | KeyCode::Down => self.move_field(1),
            KeyCode::BackTab | KeyCode::Up => self.move_field(4),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => {
                self.cursor = (self.cursor + 1).min(self.active_value().chars().count())
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.active_value().chars().count(),
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let start = Self::byte_at(self.active_value(), self.cursor - 1);
                    let end = Self::byte_at(self.active_value(), self.cursor);
                    self.active_mut().drain(start..end);
                    self.cursor -= 1;
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.active_value().chars().count() {
                    let start = Self::byte_at(self.active_value(), self.cursor);
                    let end = Self::byte_at(self.active_value(), self.cursor + 1);
                    self.active_mut().drain(start..end);
                }
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                let index = Self::byte_at(self.active_value(), self.cursor);
                self.active_mut().insert(index, c);
                self.cursor += 1;
            }
            KeyCode::Enter => {
                if self.name.is_empty() {
                    return FormResult::Error("Name must not be empty".into());
                }
                if self.password.is_empty() {
                    return FormResult::Error("Password must not be empty".into());
                }
                if !self.realm.is_empty() && self.url.is_empty() {
                    return FormResult::Error("A realm requires a URL".into());
                }
                if entries
                    .iter()
                    .enumerate()
                    .any(|(i, e)| Some(i) != self.editing && e.name == self.name)
                {
                    return FormResult::Error("An entry with that name already exists".into());
                }
                for (label, value) in [
                    ("Name", &self.name),
                    ("Username", &self.username),
                    ("URL", &self.url),
                    ("Realm", &self.realm),
                ] {
                    if value
                        .chars()
                        .any(|c| c.is_control() || mypass::is_display_spoofing_char(c))
                    {
                        return FormResult::Error(format!("{label} contains unsafe characters"));
                    }
                    if value.chars().count() > mypass::MAX_NAME_LEN {
                        return FormResult::Error(format!("{label} is too long"));
                    }
                }
                return FormResult::Save(PasswordEntry {
                    name: self.name.clone(),
                    username: self.username.clone(),
                    password: Secret::new(self.password.clone()),
                    url: (!self.url.is_empty()).then(|| self.url.clone()),
                    realm: (!self.realm.is_empty()).then(|| self.realm.clone()),
                });
            }
            _ => {}
        }
        FormResult::Continue
    }
}

fn draw_form(frame: &mut Frame, form: &Form) {
    let area = centered(70, 21, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default()
            .title(if form.editing.is_some() {
                " Edit entry "
            } else {
                " New entry "
            })
            .borders(Borders::ALL),
        area,
    );
    let inner = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: area.height.saturating_sub(2),
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner);
    let labels = ["Name", "Username", "Password", "URL", "Realm"];
    for (i, ((label, value), row)) in labels
        .iter()
        .zip(form.fields())
        .zip(rows.iter())
        .enumerate()
    {
        let available = row.width.saturating_sub(2) as usize;
        let start = if i == form.active {
            form.cursor.saturating_sub(available.saturating_sub(1))
        } else {
            0
        };
        let shown: String = if i == 2 {
            "•".repeat(value.chars().count())
        } else {
            super::sanitize(value)
        }
        .chars()
        .skip(start)
        .take(available)
        .collect();
        frame.render_widget(
            Paragraph::new(shown).block(
                Block::default()
                    .title(format!(" {label} "))
                    .borders(Borders::ALL)
                    .border_style(if i == form.active {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default()
                    }),
            ),
            *row,
        );
        if i == form.active && row.height >= 3 {
            frame.set_cursor_position((
                row.x + 1 + form.cursor.saturating_sub(start) as u16,
                row.y + 1,
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(
            form.error
                .as_deref()
                .unwrap_or("Tab/↑/↓ field  Enter save  Esc cancel"),
        )
        .style(Style::default().fg(if form.error.is_some() {
            Color::Red
        } else {
            Color::Gray
        })),
        rows[5],
    );
}

fn draw_popup(frame: &mut Frame, title: &str, text: &str, width: u16, height: u16) {
    let area = centered(width, height, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn create_edit_delete_and_choose_exit() {
        let mut app = App::new(vec![], 20);
        app.handle_key(key(KeyCode::Char('n')));
        let Mode::Edit(form) = &mut app.mode else {
            panic!()
        };
        form.name = "example".into();
        form.username = "alice".into();
        form.password = "secret".into();
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.entries[0].name, "example");
        assert!(app.dirty);
        app.handle_key(key(KeyCode::Char('e')));
        let Mode::Edit(form) = &mut app.mode else {
            panic!()
        };
        form.username = "bob".into();
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.entries[0].username, "bob");
        app.handle_key(key(KeyCode::Char('d')));
        app.handle_key(key(KeyCode::Char('y')));
        assert!(app.entries.is_empty());
        app.handle_key(key(KeyCode::Char('q')));
        assert!(matches!(app.mode, Mode::ConfirmExit));
        assert!(app.handle_key(key(KeyCode::Char('s'))));
        assert_eq!(app.exit, Exit::Save);
    }

    #[test]
    fn browse_shortcut_keys() {
        let mut app = App::new(vec![], 20);
        app.handle_key(key(KeyCode::Enter));
        app.handle_key(key(KeyCode::Delete));
        assert!(matches!(app.mode, Mode::Browse));

        app.handle_key(key(KeyCode::Insert));
        let Mode::Edit(form) = &mut app.mode else {
            panic!()
        };
        form.name = "example".into();
        form.password = "secret".into();
        app.handle_key(key(KeyCode::Enter));

        app.handle_key(key(KeyCode::Enter));
        assert!(matches!(app.mode, Mode::Edit(_)));
        app.handle_key(key(KeyCode::Esc));
        app.handle_key(key(KeyCode::Delete));
        assert!(matches!(app.mode, Mode::ConfirmDelete));
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.entries.len(), 1);
        app.handle_key(key(KeyCode::Esc));
        assert!(matches!(app.mode, Mode::ConfirmExit));
    }

    fn searchable_app() -> App {
        App::new(
            vec![
                PasswordEntry {
                    name: "Alpha".into(),
                    username: "alice".into(),
                    password: "hidden".into(),
                    url: None,
                    realm: None,
                },
                PasswordEntry {
                    name: "Beta".into(),
                    username: "bob".into(),
                    password: "hidden".into(),
                    url: Some("https://example.org".into()),
                    realm: Some("Admin".into()),
                },
            ],
            20,
        )
    }

    fn search(app: &mut App, query: &str) {
        app.handle_key(key(KeyCode::Char('/')));
        for c in query.chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
    }

    #[test]
    fn search_matches_metadata_but_never_passwords() {
        for query in ["BETA", "BOB", "EXAMPLE", "ADMIN"] {
            let mut app = searchable_app();
            search(&mut app, query);
            assert_eq!(app.visible_indices(), vec![1]);
            assert_eq!(app.selected_index(), Some(1));
            assert!(!app.dirty);
            app.handle_key(key(KeyCode::Esc));
            assert_eq!(app.visible_indices(), vec![0, 1]);
            assert_eq!(app.exit, Exit::Running);
        }
        let mut app = searchable_app();
        search(&mut app, "hidden");
        assert_eq!(app.selected_index(), None);
        app.handle_key(key(KeyCode::Delete));
        app.handle_key(key(KeyCode::Enter));
        assert!(matches!(app.mode, Mode::Browse));
    }

    #[test]
    fn filtered_edit_and_delete_target_the_visible_entry() {
        let mut app = searchable_app();
        search(&mut app, "beta");
        app.handle_key(key(KeyCode::Enter));
        let Mode::Edit(form) = &mut app.mode else {
            panic!()
        };
        assert_eq!(form.editing, Some(1));
        form.name = "Aardvark".into();
        app.handle_key(key(KeyCode::Enter));
        assert!(app.visible_indices().is_empty());
        assert!(app.message.as_deref().unwrap().contains("hidden by search"));
        app.handle_key(key(KeyCode::Esc));
        search(&mut app, "alice");
        app.handle_key(key(KeyCode::Delete));
        app.handle_key(key(KeyCode::Char('y')));
        assert_eq!(app.entries.len(), 1);
        assert_eq!(app.entries[0].name, "Aardvark");
    }

    #[test]
    fn clearing_search_preserves_selection_and_control_c_quits() {
        let mut app = searchable_app();
        search(&mut app, "beta");
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.selected_index(), Some(1));
        app.handle_key(key(KeyCode::Char('/')));
        assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert_eq!(app.exit, Exit::Clean);

        let mut app = searchable_app();
        app.dirty = true;
        app.handle_key(key(KeyCode::Char('/')));
        assert!(!app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert!(matches!(app.mode, Mode::ConfirmExit));
    }

    #[test]
    fn search_input_handles_unicode_and_shortcut_characters() {
        let mut app = searchable_app();
        app.handle_key(key(KeyCode::Char('/')));
        for c in "éqnd".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.query, "éqnd");
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Backspace));
        }
        assert_eq!(app.query, "");
        assert_eq!(app.visible_indices().len(), 2);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.exit, Exit::Running);
    }

    #[test]
    fn form_rejects_duplicates_and_realm_without_url() {
        let entries = vec![PasswordEntry {
            name: "one".into(),
            username: String::new(),
            password: "pw".into(),
            url: None,
            realm: None,
        }];
        let mut form = Form::new();
        form.name = "one".into();
        form.password = "pw".into();
        assert!(matches!(
            form.handle_key(key(KeyCode::Enter), &entries),
            FormResult::Error(_)
        ));
        form.name = "two".into();
        form.realm = "Admin".into();
        assert!(matches!(
            form.handle_key(key(KeyCode::Enter), &entries),
            FormResult::Error(_)
        ));
    }

    #[test]
    fn delete_confirmation_ignores_unrelated_keys() {
        let mut app = App::new(
            vec![PasswordEntry {
                name: "one".into(),
                username: String::new(),
                password: "pw".into(),
                url: None,
                realm: None,
            }],
            20,
        );
        app.handle_key(key(KeyCode::Char('d')));
        app.handle_key(key(KeyCode::Down));
        assert!(matches!(app.mode, Mode::ConfirmDelete));
        assert_eq!(app.entries.len(), 1);
    }

    #[test]
    fn form_can_edit_in_the_middle_of_a_field() {
        let mut form = Form::new();
        for c in "ac".chars() {
            form.handle_key(key(KeyCode::Char(c)), &[]);
        }
        form.handle_key(key(KeyCode::Left), &[]);
        form.handle_key(key(KeyCode::Char('b')), &[]);
        assert_eq!(form.name, "abc");
        form.handle_key(key(KeyCode::Backspace), &[]);
        assert_eq!(form.name, "ac");
        form.handle_key(key(KeyCode::Delete), &[]);
        assert_eq!(form.name, "a");
    }
}
