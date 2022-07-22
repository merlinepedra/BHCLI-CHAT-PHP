mod util;

use base64::decode;
use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use clap::{AppSettings, Clap};
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use colors_transform::{Color, Rgb};
use crossbeam_channel::{self, after, select, Select};
use crossterm::event;
use crossterm::event::Event as CEvent;
use crossterm::event::{MouseEvent, MouseEventKind};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use http::StatusCode;
use image;
use image::GenericImageView;
use lazy_static::lazy_static;
use linkify::LinkFinder;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use regex::Regex;
use reqwest::blocking::multipart;
use reqwest::blocking::Client;
use rodio::{source::Source, Decoder, OutputStream};
use select::document::Document;
use select::predicate::{And, Attr, Name};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error;
use std::fs;
use std::io::Cursor;
use std::io::{self, Write};
use std::process;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time;
use std::time::Duration;
use std::time::Instant;
use termage;
use textwrap;
use tui::layout::Rect;
use tui::style::Color as tuiColor;
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use unicode_width::UnicodeWidthStr;
use util::StatefulList;

const LANG: &str = "en";
const SEND_TO_ALL: &str = "s *";
const SEND_TO_MEMBERS: &str = "s ?";
const SEND_TO_STAFFS: &str = "s %";
const SEND_TO_ADMINS: &str = "s _";
const SOUND1: &[u8] = include_bytes!("sound1.mp3");
const DKF_URL: &str = "http://dkforestseeaaq2dqz2uflmlsybvnq2irzn4ygyvu53oazyorednviid.onion";
const BHCLI_BLOG_URL: &str =
    "http://dkforestseeaaq2dqz2uflmlsybvnq2irzn4ygyvu53oazyorednviid.onion/bhcli";
const BAN_IMPOSTERS: bool = true;
const SERVER_DOWN_500_ERR: &str = "500 Internal Server Error, server down";
const SERVER_DOWN_ERR: &str = "502 Bad Gateway, server down";
const KICKED_ERR: &str = "You have been kicked";
const REG_ERR: &str = "This nickname is a registered member";
const NICKNAME_ERR: &str = "Invalid nickname";
const CAPTCHA_WG_ERR: &str = "Wrong Captcha";
const CAPTCHA_USED_ERR: &str = "Captcha already used or timed out";
const UNKNOWN_ERR: &str = "Unknown error";
const N0TR1V: &str = "n0tr1v";
const DNMX_URL: &str = "http://hxuzjtocnzvv5g2rtg2bhwkcbupmk7rclb6lly3fo4tvqkk5oyrv3nid.onion";

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

lazy_static! {
    static ref SESSION_RGX: Regex = Regex::new(r#"session=([^&]+)"#).unwrap();
    static ref COLOR_RGX: Regex = Regex::new(r#"color:\s*([#\w]+)\s*;"#).unwrap();
    static ref COLOR1_RGX: Regex = Regex::new(r#"^#([0-9A-Fa-f]{6})$"#).unwrap();
    static ref PM_RGX: Regex = Regex::new(r#"^/pm ([^\s]+) (.*)"#).unwrap();
    static ref KICK_RGX: Regex = Regex::new(r#"^/(?:kick|k) ([^\s]+)\s?(.*)"#).unwrap();
    static ref IGNORE_RGX: Regex = Regex::new(r#"^/ignore ([^\s]+)"#).unwrap();
    static ref UNIGNORE_RGX: Regex = Regex::new(r#"^/unignore ([^\s]+)"#).unwrap();
    static ref DLX_RGX: Regex = Regex::new(r#"^/dl([\d]+)$"#).unwrap();
    static ref UPLOAD_RGX: Regex = Regex::new(r#"^/u\s([^\s]+)\s?(?:@([^\s]+)\s)?(.*)$"#).unwrap();
    static ref FIND_RGX: Regex = Regex::new(r#"^/f\s(.*)$"#).unwrap();
    static ref NEW_NICKNAME_RGX: Regex = Regex::new(r#"^/nick\s(.*)$"#).unwrap();
    static ref NEW_COLOR_RGX: Regex = Regex::new(r#"^/color\s(.*)$"#).unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
enum Typ {
    BHC,
    Custom,
}

impl Typ {
    fn bhc() -> Self {
        Typ::BHC
    }
}

fn default_empty_str() -> String {
    "".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
struct Profile {
    username: String,
    password: String,
    #[serde(default = "Typ::bhc")]
    typ: Typ,
    #[serde(default = "default_empty_str")]
    url: String,
    #[serde(default = "default_empty_str")]
    date_format: String,
    #[serde(default = "default_empty_str")]
    page_php: String,
    #[serde(default = "default_empty_str")]
    members_tag: String,
    #[serde(default = "default_empty_str")]
    keepalive_send_to: String,
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct MyConfig {
    dkf_api_key: Option<String>,
    profiles: HashMap<String, Profile>,
}

#[derive(Clap)]
#[clap(
    name = "bhcli",
    version = "0.0.1",
    author = "n0tr1v <n0tr1v@protonmail.com>"
)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(long, env = "DKF_API_KEY")]
    dkf_api_key: Option<String>,
    #[clap(short, long, env = "BHC_USERNAME")]
    username: Option<String>,
    #[clap(short, long, env = "BHC_PASSWORD")]
    password: Option<String>,
    #[clap(short, long, env = "BHC_MANUAL_CAPTCHA")]
    manual_captcha: bool,
    #[clap(short, long, env = "BHC_GUEST_COLOR")]
    guest_color: Option<String>,
    #[clap(short, long, env = "BHC_REFRESH_RATE", default_value = "5")]
    refresh_rate: u64,
    #[clap(long, env = "BHC_MAX_LOGIN_RETRY", default_value = "5")]
    max_login_retry: isize,
    #[clap(long)]
    url: Option<String>,
    #[clap(long)]
    page_php: Option<String>,
    #[clap(long)]
    datetime_fmt: Option<String>,
    #[clap(long)]
    members_tag: Option<String>,
    #[clap(short, long)]
    dan: bool,
    #[clap(
        short,
        long,
        env = "BHC_PROXY_URL",
        default_value = "socks5h://127.0.0.1:9050"
    )]
    socks_proxy_url: String,
    #[clap(long, env = "DNMX_USERNAME")]
    dnmx_username: Option<String>,
    #[clap(long, env = "DNMX_PASSWORD")]
    dnmx_password: Option<String>,
    #[clap(short = 'c', long, default_value = "default")]
    profile: String,
}

struct LeChatPHPConfig {
    url: String,
    datetime_fmt: String,
    page_php: String,
    keepalive_send_to: Option<String>,
    members_tag: String,
    staffs_tag: String,
}

impl LeChatPHPConfig {
    fn new_black_hat_chat_config() -> Self {
        Self {
            url: "http://blkhatjxlrvc5aevqzz5t6kxldayog6jlx5h7glnu44euzongl4fh5ad.onion".to_owned(),
            datetime_fmt: "%m-%d %H:%M:%S".to_owned(),
            page_php: "index.php".to_owned(),
            keepalive_send_to: Some("0".to_owned()),
            members_tag: "[M] ".to_owned(),
            staffs_tag: "[Staff] ".to_owned(),
        }
    }

    fn new_dans_chat_config() -> Self {
        Self {
            url: "http://danschat356lctri3zavzh6fbxg2a7lo6z3etgkctzzpspewu7zdsaqd.onion".to_owned(),
            datetime_fmt: "%d-%m %H:%M:%S".to_owned(),
            page_php: "chat.php".to_owned(),
            keepalive_send_to: None,
            members_tag: "[Members] ".to_owned(),
            staffs_tag: "[Staff] ".to_owned(),
        }
    }
}

struct BaseClient {
    username: String,
    password: String,
}

struct LeChatPHPClient<'a> {
    base_client: BaseClient,
    guest_color: String,
    client: &'a Client,
    session: String,
    config: LeChatPHPConfig,
    dkf_api_key: Option<String>,
    manual_captcha: bool,
    refresh_rate: u64,
    max_login_retry: isize,

    is_muted: Arc<Mutex<bool>>,
    show_sys: bool,
    display_guest_view: bool,
    display_hidden_msgs: bool,
    tx: crossbeam_channel::Sender<PostType>,
    rx: Arc<Mutex<crossbeam_channel::Receiver<PostType>>>,

    color_tx: crossbeam_channel::Sender<()>,
    color_rx: Arc<Mutex<crossbeam_channel::Receiver<()>>>,
}

impl<'a> LeChatPHPClient<'a> {
    fn run_forever(&mut self) {
        let max_retry = self.max_login_retry;
        let mut attempt = 0;
        loop {
            if let Err(e) = self.login() {
                if e.to_string() == KICKED_ERR
                    || e.to_string() == REG_ERR
                    || e.to_string() == NICKNAME_ERR
                    || e.to_string() == UNKNOWN_ERR
                {
                    eprintln!("{:?}", e.to_string());
                    break;
                } else if e.to_string() == CAPTCHA_WG_ERR || e.to_string() == CAPTCHA_USED_ERR {
                } else if e.to_string() == SERVER_DOWN_ERR || e.to_string() == SERVER_DOWN_500_ERR {
                    eprintln!("{}", e.to_string());
                } else if let Some(err) = e.downcast_ref::<reqwest::Error>() {
                    if err.is_connect() {
                        eprintln!("{:?}\nIs tor proxy enabled ?", err.to_string());
                        break;
                    } else if err.is_timeout() {
                        eprintln!("timeout: {:?}", err.to_string());
                    } else {
                        eprintln!("{:?}", err.to_string());
                    }
                } else {
                    eprintln!("unknown error: {:?}", e.to_string());
                }
            } else {
                attempt = 0;
                match self.get_msgs() {
                    Ok(ExitSignal::NeedLogin) => {}
                    Ok(ExitSignal::Terminate) => return,
                    Err(e) => eprintln!("{:?}", e),
                }
            }
            attempt += 1;
            if max_retry > 0 && attempt > max_retry {
                break;
            }
            self.session = "".to_owned();
            let retry_in = time::Duration::from_secs(2);
            let mut msg = format!("retry login in {:?}, attempt: {}", retry_in, attempt);
            if max_retry > 0 {
                msg += &format!("/{}", max_retry);
            }
            println!("{}", msg);
            thread::sleep(retry_in);
        }
    }

    fn start_keepalive_thread(
        &self,
        exit_rx: crossbeam_channel::Receiver<ExitSignal>,
        last_post_rx: crossbeam_channel::Receiver<bool>,
    ) -> thread::JoinHandle<()> {
        let tx = self.tx.clone();
        let send_to = self.config.keepalive_send_to.clone();
        thread::spawn(move || loop {
            let timeout = after(time::Duration::from_secs(60 * 75));
            select! {
                // Whenever we send a message to chat server,
                // we will receive a message on this channel
                // and reset the timer for next keepalive.
                recv(&last_post_rx) -> _ => {},
                recv(&exit_rx) -> _ => return,
                recv(&timeout) -> _ => {
                    tx.send(PostType::Post("<keepalive>".to_owned(), send_to.clone())).unwrap();
                    tx.send(PostType::DeleteLast).unwrap();
                },
            }
        })
    }

    // Thread that POST to chat server
    fn start_post_msg_thread(
        &self,
        exit_rx: crossbeam_channel::Receiver<ExitSignal>,
        last_post_tx: crossbeam_channel::Sender<bool>,
    ) -> thread::JoinHandle<()> {
        let client = self.client.clone();
        let rx = Arc::clone(&self.rx);
        let full_url = format!("{}/{}", &self.config.url, &self.config.page_php);
        let url = format!("{}?action=post&session={}", &full_url, self.session);
        let session = self.session.clone();
        thread::spawn(move || loop {
            let rx = rx.lock().unwrap();

            let mut sel = Select::new();
            let oper1 = sel.recv(&rx);
            let oper2 = sel.recv(&exit_rx);
            let oper = sel.select();

            if oper.index() == oper2 {
                if let Ok(_) = oper.recv(&exit_rx) {
                    return;
                }
            } else if oper.index() == oper1 {
                if let Ok(post_type_recv) = oper.recv(&rx) {
                    loop {
                        let post_type = post_type_recv.clone();
                        let resp = match client.get(url.clone()).send() {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!("failed to send request: {:?}", e);
                                continue;
                            }
                        };
                        let resp_text = resp.text().unwrap();
                        let doc = Document::from(resp_text.as_str());
                        let nc = doc.select(Attr("name", "nc")).next().unwrap();
                        let nc_value = nc.attr("value").unwrap().to_owned();
                        let postid = doc.select(Attr("name", "postid")).next().unwrap();
                        let postid_value = postid.attr("value").unwrap().to_owned();
                        let mut params: Vec<(&str, String)> = vec![
                            ("lang", LANG.to_owned()),
                            ("nc", nc_value.to_owned()),
                            ("session", session.clone()),
                        ];

                        if let PostType::Clean(date, text) = post_type {
                            if let Err(_) =
                                delete_message(&client, &full_url, &mut params, date, text)
                            {
                                continue;
                            }
                            break;
                        }

                        let mut req = client.post(&full_url);
                        let mut form: Option<reqwest::blocking::multipart::Form> = None;

                        match post_type {
                            PostType::Post(msg, send_to) => {
                                params.extend(vec![
                                    ("action", "post".to_owned()),
                                    ("postid", postid_value.to_owned()),
                                    ("message", msg.clone()),
                                    ("sendto", send_to.unwrap_or(SEND_TO_ALL.to_owned())),
                                ]);
                            }
                            PostType::NewNickname(new_nickname) => {
                                if let Err(e) =
                                    set_profile_base_info(&client, &full_url, &mut params)
                                {
                                    eprintln!("{:?}", e);
                                    continue;
                                }
                                params.extend(vec![
                                    ("do", "save".to_owned()),
                                    ("timestamps", "on".to_owned()),
                                    ("newnickname", new_nickname),
                                ]);
                            }
                            PostType::NewColor(new_color) => {
                                if let Err(e) =
                                    set_profile_base_info(&client, &full_url, &mut params)
                                {
                                    eprintln!("{:?}", e);
                                    continue;
                                }
                                params.extend(vec![
                                    ("do", "save".to_owned()),
                                    ("timestamps", "on".to_owned()),
                                    ("colour", new_color),
                                ]);
                            }
                            PostType::Ignore(username) => {
                                if let Err(e) =
                                    set_profile_base_info(&client, &full_url, &mut params)
                                {
                                    eprintln!("{:?}", e);
                                    continue;
                                }
                                params.extend(vec![
                                    ("do", "save".to_owned()),
                                    ("timestamps", "on".to_owned()),
                                    ("ignore", username),
                                ]);
                            }
                            PostType::Unignore(username) => {
                                if let Err(e) =
                                    set_profile_base_info(&client, &full_url, &mut params)
                                {
                                    eprintln!("{:?}", e);
                                    continue;
                                }
                                params.extend(vec![
                                    ("do", "save".to_owned()),
                                    ("timestamps", "on".to_owned()),
                                    ("unignore", username),
                                ]);
                            }
                            PostType::Profile(new_color, new_nickname) => {
                                if let Err(e) =
                                    set_profile_base_info(&client, &full_url, &mut params)
                                {
                                    eprintln!("{:?}", e);
                                    continue;
                                }
                                params.extend(vec![
                                    ("do", "save".to_owned()),
                                    ("timestamps", "on".to_owned()),
                                    ("colour", new_color),
                                    ("newnickname", new_nickname),
                                ]);
                            }
                            PostType::Kick(msg, send_to) => {
                                params.extend(vec![
                                    ("action", "post".to_owned()),
                                    ("postid", postid_value.to_owned()),
                                    ("message", msg),
                                    ("sendto", send_to),
                                    ("kick", "kick".to_owned()),
                                    ("what", "purge".to_owned()),
                                ]);
                            }
                            PostType::DeleteLast | PostType::DeleteAll => {
                                params.extend(vec![("action", "delete".to_owned())]);
                                if let PostType::DeleteAll = post_type {
                                    params.extend(vec![
                                        ("sendto", SEND_TO_ALL.to_owned()),
                                        ("confirm", "yes".to_owned()),
                                        ("what", "all".to_owned()),
                                    ]);
                                } else {
                                    params.extend(vec![
                                        ("sendto", "".to_owned()),
                                        ("what", "last".to_owned()),
                                    ]);
                                }
                            }
                            PostType::Upload(file_path, send_to, msg) => {
                                form = Some(
                                    multipart::Form::new()
                                        .text("lang", LANG.to_owned())
                                        .text("nc", nc_value.to_owned())
                                        .text("session", session.clone())
                                        .text("action", "post".to_owned())
                                        .text("postid", postid_value.to_owned())
                                        .text("message", msg)
                                        .text("sendto", send_to.to_owned())
                                        .text("what", "purge".to_owned())
                                        .file("file", file_path)
                                        .unwrap(),
                                );
                            }
                            PostType::Clean(_, _) => {}
                        }

                        if let Some(form_content) = form {
                            req = req.multipart(form_content);
                        } else {
                            req = req.form(&params);
                        }
                        if let Err(err) = req.send() {
                            if err.is_timeout() {
                                eprintln!("{:?}", err.to_string());
                                continue;
                            } else {
                                eprintln!("{:?}", err.to_string());
                            }
                        }
                        break;
                    }
                    last_post_tx.send(true).unwrap();
                }
            }
        })
    }

    // Thread that update messages every "refresh_rate"
    fn start_get_msgs_thread(
        &self,
        sig: &Arc<Mutex<Sig>>,
        messages: &Arc<Mutex<Vec<Message>>>,
        users: &Arc<Mutex<Users>>,
        messages_updated_tx: crossbeam_channel::Sender<bool>,
    ) -> thread::JoinHandle<()> {
        let client = self.client.clone();
        let messages = Arc::clone(&messages);
        let users = Arc::clone(&users);
        let session = self.session.clone();
        let username = self.base_client.username.clone();
        let refresh_rate = self.refresh_rate.clone();
        let base_url = self.config.url.clone();
        let page_php = self.config.page_php.clone();
        let datetime_fmt = self.config.datetime_fmt.clone();
        let is_muted = Arc::clone(&self.is_muted);
        let exit_rx = sig.lock().unwrap().clone();
        let sig = Arc::clone(sig);
        let tx = self.tx.clone();
        let members_tag = self.config.members_tag.clone();
        let h = thread::spawn(move || loop {
            let (_stream, stream_handle) = OutputStream::try_default().unwrap();
            let source = Decoder::new_mp3(Cursor::new(SOUND1)).unwrap();

            let url = format!(
                "{}/{}?action=view&session={}&lang={}",
                base_url, page_php, session, LANG
            );
            if let Ok(resp) = client.get(url).send() {
                if let Ok(resp_text) = resp.text() {
                    let resp_text = resp_text.replace("<br>", "\n");
                    let doc = Document::from(resp_text.as_str());
                    let mut should_notify = false;
                    {
                        let mut messages = messages.lock().unwrap();
                        if let Ok(new_messages) = extract_messages(&doc) {
                            let parse_date = |date: &str| -> NaiveDateTime {
                                let now = chrono::offset::Utc::now();
                                let date_fmt = format!("%Y-{}", datetime_fmt);
                                NaiveDateTime::parse_from_str(
                                    format!("{}-{}", now.year(), date).as_str(),
                                    date_fmt.as_str(),
                                )
                                .unwrap()
                            };

                            if let Some(last_known_msg) = messages.get(0) {
                                let msg = last_known_msg;
                                let parsed_dt = parse_date(&msg.date);
                                for new_msg in &new_messages {
                                    let new_parsed_dt = parse_date(&new_msg.date);

                                    if parsed_dt > new_parsed_dt
                                        || (new_msg.date == msg.date && msg.text == new_msg.text)
                                    {
                                        break;
                                    }

                                    if let Some((from, to_opt, msg)) =
                                        get_message(&new_msg.text, &members_tag)
                                    {
                                        // Process new messages

                                        // !bhcli filters
                                        if msg == "!bhcli" && username == N0TR1V {
                                            let msg = format!("@{} -> {}", from, BHCLI_BLOG_URL)
                                                .to_owned();
                                            tx.send(PostType::Post(msg, None)).unwrap();
                                        } else if msg == "/logout"
                                            && from == "STUXNET"
                                            && username == N0TR1V
                                        {
                                            eprintln!("forced logout by {}", from);
                                            sig.lock().unwrap().signal(ExitSignal::Terminate);
                                            return;
                                        }
                                        // Notify when tagged
                                        if msg.contains(format!("@{}", &username).as_str()) {
                                            should_notify = true;
                                        }
                                        // Notify when PM is received
                                        if let Some(to) = to_opt {
                                            if to == username && msg != "!up" {
                                                should_notify = true;
                                            }
                                        }
                                    }
                                }
                            }

                            // Build messages vector. Tag deleted messages.
                            let mut msgs_repl = Vec::new();
                            let mut old_msg_ptr = 0;
                            let mut new_msg_ptr = 0;
                            let mut i = 0;
                            while old_msg_ptr < messages.len() || new_msg_ptr < new_messages.len() {
                                if let Some(old_msg) = messages.get(old_msg_ptr) {
                                    if let Some(new_msg) = new_messages.get(new_msg_ptr) {
                                        let new_parsed_dt = parse_date(&new_msg.date);
                                        let parsed_dt = parse_date(&old_msg.date);
                                        if new_parsed_dt > parsed_dt {
                                            msgs_repl.push(new_msg.clone());
                                            new_msg_ptr += 1;
                                        } else if new_parsed_dt == parsed_dt {
                                            if old_msg.text.text() == new_msg.text.text() {
                                                msgs_repl.push(old_msg.clone());
                                            } else {
                                                msgs_repl.push(new_msg.clone());
                                            }
                                            new_msg_ptr += 1;
                                            old_msg_ptr += 1;
                                        } else {
                                            let mut tmp = old_msg.clone();
                                            tmp.deleted = true;
                                            msgs_repl.push(tmp);
                                            old_msg_ptr += 1;
                                        }
                                    } else {
                                        msgs_repl.push(old_msg.clone());
                                        old_msg_ptr += 1;
                                    }
                                } else if let Some(new_msg) = new_messages.get(new_msg_ptr) {
                                    msgs_repl.push(new_msg.clone());
                                    new_msg_ptr += 1;
                                }
                                i += 1;
                                if i > 2000 {
                                    break;
                                }
                            }

                            // Notify new messages has arrived.
                            // This ensure that we redraw the messages on the screen right away.
                            // Otherwise, the screen would not redraw until a keyboard event occurs.
                            messages_updated_tx.send(true).unwrap();
                            // Update "messages" with new value
                            *messages = msgs_repl;
                        } else {
                            // Failed to get messages, probably need relogin
                            sig.lock().unwrap().signal(ExitSignal::NeedLogin);
                            return;
                        }
                    }
                    let muted = { *is_muted.lock().unwrap() };
                    if should_notify && !muted {
                        if let Err(err) = stream_handle.play_raw(source.convert_samples()) {
                            eprintln!("{}", err);
                        }
                    }
                    {
                        let mut users = users.lock().unwrap();
                        ban_imposters(&tx, &username, &users);
                        *users = extract_users(&doc);
                    }
                }
            }

            let timeout = after(time::Duration::from_secs(refresh_rate));
            select! {
                recv(&exit_rx) -> _ => return,
                recv(&timeout) -> _ => {},
            }
        });
        h
    }

    fn get_msgs(&mut self) -> Result<ExitSignal> {
        let terminate_signal: ExitSignal;

        let messages: Arc<Mutex<Vec<Message>>> = Arc::new(Mutex::new(Vec::new()));
        let users: Arc<Mutex<Users>> = Arc::new(Mutex::new(Users::default()));

        // Create default app state
        let mut app = App::default();

        // Each threads gets a clone of the receiver.
        // When someone calls ".signal", all threads recieve it,
        // and knows that they have to terminate.
        let sig = Arc::new(Mutex::new(Sig::new()));

        let (messages_updated_tx, messages_updated_rx) = crossbeam_channel::unbounded();
        let (last_post_tx, last_post_rx) = crossbeam_channel::unbounded();

        let h1 = self.start_keepalive_thread(sig.lock().unwrap().clone(), last_post_rx);
        let h2 = self.start_post_msg_thread(sig.lock().unwrap().clone(), last_post_tx);
        let h3 = self.start_get_msgs_thread(&sig, &messages, &users, messages_updated_tx);

        // Terminal initialization
        let mut stdout = io::stdout();
        enable_raw_mode().unwrap();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Setup event handlers
        let (events, h4) = Events::with_config(Config {
            messages_updated_rx,
            exit_rx: sig.lock().unwrap().clone(),
            tick_rate: time::Duration::from_millis(250),
        });

        loop {
            {
                app.is_muted = *self.is_muted.lock().unwrap();
                app.show_sys = self.show_sys;
                app.display_guest_view = self.display_guest_view;
                app.display_hidden_msgs = self.display_hidden_msgs;
                app.members_tag = self.config.members_tag.clone();
                app.staffs_tag = self.config.staffs_tag.clone();
            }
            // Draw UI
            terminal.draw(|f| {
                draw_terminal_frame(f, &mut app, &messages, &users);
            })?;

            // Handle input
            match self.handle_input(&events, &mut app, &messages, &users) {
                Err(ExitSignal::Terminate) => {
                    terminate_signal = ExitSignal::Terminate;
                    sig.lock().unwrap().signal(terminate_signal.clone());
                    break;
                }
                Err(ExitSignal::NeedLogin) => {
                    terminate_signal = ExitSignal::NeedLogin;
                    sig.lock().unwrap().signal(terminate_signal.clone());
                    break;
                }
                Ok(_) => continue,
            };
        }

        // Cleanup before leaving
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        terminal.clear()?;
        terminal.set_cursor(0, 0)?;

        h1.join().unwrap();
        h2.join().unwrap();
        h3.join().unwrap();
        h4.join().unwrap();

        Ok(terminate_signal)
    }

    fn post_msg(&self, post_type: PostType) -> Result<()> {
        self.tx.send(post_type)?;
        Ok(())
    }

    fn login(&mut self) -> Result<()> {
        // If we provided a session, skip login process
        if self.session != "" {
            return Ok(());
        }

        // Get login page
        let login_url = format!("{}/{}", &self.config.url, &self.config.page_php);
        let resp = self.client.get(&login_url).send()?;
        if resp.status() == StatusCode::BAD_GATEWAY {
            return Err(SERVER_DOWN_ERR.into());
        }
        let resp = resp.text()?;
        let doc = Document::from(resp.as_str());

        // Post login form
        let mut params = vec![
            ("action", "login".to_owned()),
            ("lang", LANG.to_owned()),
            ("nick", self.base_client.username.clone()),
            ("pass", self.base_client.password.clone()),
            ("colour", self.guest_color.clone()),
        ];

        if let Some(captcha_value) = doc
            .select(And(Name("input"), Attr("name", "challenge")))
            .next()
        {
            let captcha_value = captcha_value.attr("value").unwrap();

            let mut captcha_input = String::new();
            if self.manual_captcha {
                let captcha_img = doc.select(Name("img")).next().unwrap().attr("src").unwrap();

                if let Some(dkf_api_key) = self.dkf_api_key.clone() {
                    // If we have the DKF_API_KEY, auto solve captcha using the api
                    let params = vec![("captcha", captcha_img)];
                    let resp = self
                        .client
                        .post(format!("{}/api/v1/captcha/solver", DKF_URL))
                        .header("DKF_API_KEY", dkf_api_key)
                        .form(&params)
                        .send()?;
                    let resp = resp.text()?;
                    let rgx = Regex::new(r#""answer": "([^"]+)""#)?
                        .captures(resp.as_str())
                        .unwrap();
                    let answer = rgx.get(1).unwrap().as_str();
                    captcha_input = answer.to_owned();
                } else {
                    // Otherwise, save the captcha on disk and prompt user for answer
                    let img_decoded =
                        decode(captcha_img.strip_prefix("data:image/gif;base64,").unwrap())?;
                    let img = image::load_from_memory(&img_decoded).unwrap();
                    let img_buf = image::imageops::resize(
                        &img,
                        img.width() * 4,
                        img.height() * 4,
                        image::imageops::FilterType::Nearest,
                    );
                    // Save captcha as file on disk
                    img_buf.save("captcha.gif").unwrap();

                    termage::display_image("captcha.gif", img.width(), img.height());

                    // Enter captcha
                    print!("captcha: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut captcha_input).unwrap();
                    trim_newline(&mut captcha_input);
                }
            } else {
                // Captcha is not actually required for memebers (BHC)
                captcha_input = "12345".to_owned();
            }

            params.extend(vec![
                ("challenge", captcha_value.to_owned()),
                ("captcha", captcha_input.clone()),
            ]);
        }

        let resp = self.client.post(&login_url).form(&params).send()?;
        match resp.status() {
            StatusCode::BAD_GATEWAY => return Err(SERVER_DOWN_ERR.into()),
            StatusCode::INTERNAL_SERVER_ERROR => return Err(SERVER_DOWN_500_ERR.into()),
            _ => {}
        }
        let mut resp = resp.text()?;
        if resp.contains(CAPTCHA_USED_ERR) {
            return Err(CAPTCHA_USED_ERR.into());
        } else if resp.contains(CAPTCHA_WG_ERR) {
            return Err(CAPTCHA_WG_ERR.into());
        } else if resp.contains(REG_ERR) {
            return Err(REG_ERR.into());
        } else if resp.contains(NICKNAME_ERR) {
            return Err(NICKNAME_ERR.into());
        } else if resp.contains(KICKED_ERR) {
            return Err(KICKED_ERR.into());
        }

        let mut doc = Document::from(resp.as_str());
        if let Some(body) = doc.select(Name("body")).next() {
            if let Some(body_class) = body.attr("class") {
                if body_class == "error" {
                    if let Some(h2) = doc.select(Name("h2")).next() {
                        eprintln!("{}", h2.text());
                    }
                    return Err(UNKNOWN_ERR.into());
                } else if body_class == "failednotice" {
                    eprintln!("failed logins: {}", body.text());
                    let nc = doc.select(Attr("name", "nc")).next().unwrap();
                    let nc_value = nc.attr("value").unwrap().to_owned();
                    let params: Vec<(&str, String)> = vec![
                        ("lang", LANG.to_owned()),
                        ("nc", nc_value.to_owned()),
                        ("action", "login".to_owned()),
                    ];
                    resp = self.client.post(&login_url).form(&params).send()?.text()?;
                    doc = Document::from(resp.as_str());
                }
            }
        }

        let iframe = match doc.select(Attr("name", "view")).next() {
            Some(view) => view,
            None => {
                fs::write("./dump_login_err.html", resp.as_str()).unwrap();
                panic!("failed to get view iframe");
            }
        };
        let iframe_src = iframe.attr("src").unwrap();

        let session_captures = SESSION_RGX.captures(iframe_src).unwrap();
        let session = session_captures.get(1).unwrap().as_str();

        self.session = session.to_owned();
        Ok(())
    }

    fn logout(&mut self) -> Result<()> {
        let full_url = format!("{}/{}", &self.config.url, &self.config.page_php);
        let params = [
            ("action", "logout"),
            ("session", &self.session),
            ("lang", LANG),
        ];
        self.client.post(&full_url).form(&params).send()?;
        self.session = "".to_owned();
        Ok(())
    }

    fn start_cycle(&self, color_only: bool) {
        let username = self.base_client.username.clone();
        let tx = self.tx.clone();
        let color_rx = Arc::clone(&self.color_rx);
        thread::spawn(move || {
            let mut idx = 0;
            let colors = vec![
                "#ff3366", "#ff6633", "#FFCC33", "#33FF66", "#33FFCC", "#33CCFF", "#3366FF",
                "#6633FF", "#CC33FF", "#efefef",
            ];
            loop {
                let color_rx = color_rx.lock().unwrap();
                let timeout = after(time::Duration::from_millis(5200));
                select! {
                    recv(&color_rx) -> _ => break,
                    recv(&timeout) -> _ => {}
                }
                idx = (idx + 1) % colors.len();
                let color = colors[idx].to_owned();
                if !color_only {
                    let name = format!("{}{}", username, random_string(14));
                    eprintln!("New name : {}", name);
                    tx.send(PostType::Profile(color, name)).unwrap();
                } else {
                    tx.send(PostType::NewColor(color)).unwrap();
                }
                // tx.send(PostType::Post("!up".to_owned(), Some(username.clone())))
                //     .unwrap();
                // tx.send(PostType::DeleteLast).unwrap();
            }
            let msg = PostType::Profile("#90ee90".to_owned(), username);
            tx.send(msg).unwrap();
        });
    }

    fn handle_input(
        &mut self,
        events: &Events,
        app: &mut App,
        messages: &Arc<Mutex<Vec<Message>>>,
        users: &Arc<Mutex<Users>>,
    ) -> std::result::Result<(), ExitSignal> {
        match events.next() {
            Ok(Event::NeedLogin) => return Err(ExitSignal::NeedLogin),
            Ok(Event::Terminate) => return Err(ExitSignal::Terminate),
            Ok(Event::Input(evt)) => self.handle_event(app, messages, users, evt),
            _ => Ok(()),
        }
    }

    fn handle_event(
        &mut self,
        app: &mut App,
        messages: &Arc<Mutex<Vec<Message>>>,
        users: &Arc<Mutex<Users>>,
        event: crossterm::event::Event,
    ) -> std::result::Result<(), ExitSignal> {
        match event {
            crossterm::event::Event::Resize(_cols, _rows) => Ok(()),
            crossterm::event::Event::Key(key_event) => {
                self.handle_key_event(app, messages, users, key_event)
            }
            crossterm::event::Event::Mouse(mouse_event) => {
                self.handle_mouse_event(app, mouse_event)
            }
        }
    }

    fn handle_key_event(
        &mut self,
        app: &mut App,
        messages: &Arc<Mutex<Vec<Message>>>,
        users: &Arc<Mutex<Users>>,
        key_event: crossterm::event::KeyEvent,
    ) -> std::result::Result<(), ExitSignal> {
        match app.input_mode {
            InputMode::LongMessage => {
                self.handle_long_message_mode_key_event(app, key_event, messages)
            }
            InputMode::Normal => self.handle_normal_mode_key_event(app, key_event, messages),
            InputMode::Editing => self.handle_editing_mode_key_event(app, key_event, users),
        }
    }

    fn handle_long_message_mode_key_event(
        &mut self,
        app: &mut App,
        key_event: crossterm::event::KeyEvent,
        messages: &Arc<Mutex<Vec<Message>>>,
    ) -> std::result::Result<(), ExitSignal> {
        match key_event {
            KeyEvent {
                code: KeyCode::Enter,
                modifiers: KeyModifiers::NONE,
            }
            | KeyEvent {
                code: KeyCode::Esc,
                modifiers: KeyModifiers::NONE,
            } => {
                app.long_message = None;
                app.input_mode = InputMode::Normal;
            }
            KeyEvent {
                code: KeyCode::Char('d'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(item) = app.items.items.get(idx) {
                        self.post_msg(PostType::Clean(item.date.to_owned(), item.text.text()))
                            .unwrap();
                        let mut messages = messages.lock().unwrap();
                        if let Some(pos) = messages
                            .iter()
                            .position(|m| m.date == item.date && m.text.text() == item.text.text())
                        {
                            messages[pos].hide = !messages[pos].hide;
                        }
                        app.long_message = None;
                        app.input_mode = InputMode::Normal;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_normal_mode_key_event(
        &mut self,
        app: &mut App,
        key_event: crossterm::event::KeyEvent,
        messages: &Arc<Mutex<Vec<Message>>>,
    ) -> std::result::Result<(), ExitSignal> {
        match key_event {
            KeyEvent {
                code: KeyCode::Char('/'),
                modifiers: KeyModifiers::NONE,
            } => {
                app.items.unselect();
                app.input = "/".to_owned();
                app.input_idx = app.input.width();
                app.input_mode = InputMode::Editing;
            }
            KeyEvent {
                code: KeyCode::Char('j'),
                modifiers: KeyModifiers::NONE,
            }
            | KeyEvent {
                code: KeyCode::Down,
                modifiers: KeyModifiers::NONE,
            } => {
                app.items.next();
            }
            KeyEvent {
                code: KeyCode::Char('k'),
                modifiers: KeyModifiers::NONE,
            }
            | KeyEvent {
                code: KeyCode::Up,
                modifiers: KeyModifiers::NONE,
            } => {
                app.items.previous();
            }
            KeyEvent {
                code: KeyCode::Enter,
                modifiers: KeyModifiers::NONE,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(item) = app.items.items.get(idx) {
                        app.long_message = Some(item.clone());
                        app.input_mode = InputMode::LongMessage;
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Backspace,
                modifiers: KeyModifiers::NONE,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(item) = app.items.items.get(idx) {
                        let mut messages = messages.lock().unwrap();
                        if let Some(pos) = messages
                            .iter()
                            .position(|m| m.date == item.date && m.text.text() == item.text.text())
                        {
                            if item.deleted {
                                messages.remove(pos);
                            } else {
                                messages[pos].hide = !messages[pos].hide;
                            }
                        }
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('y'),
                modifiers: KeyModifiers::NONE,
            }
            | KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(item) = app.items.items.get(idx) {
                        if let Some(upload_link) = &item.upload_link {
                            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                            let mut out = format!("{}{}", self.config.url, upload_link);
                            if let Some((_, _, msg)) =
                                get_message(&item.text, &self.config.members_tag)
                            {
                                out = format!("{} {}", msg, out);
                            }
                            ctx.set_contents(out).unwrap();
                        } else if let Some((_, _, msg)) =
                            get_message(&item.text, &self.config.members_tag)
                        {
                            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                            ctx.set_contents(msg).unwrap();
                        }
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('Y'),
                modifiers: KeyModifiers::SHIFT,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(item) = app.items.items.get(idx) {
                        if let Some(upload_link) = &item.upload_link {
                            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                            let out = format!("{}{}", self.config.url, upload_link);
                            ctx.set_contents(out).unwrap();
                        } else if let Some((_, _, msg)) =
                            get_message(&item.text, &self.config.members_tag)
                        {
                            let finder = LinkFinder::new();
                            let links: Vec<_> = finder.links(msg.as_str()).collect();
                            if let Some(link) = links.get(0) {
                                let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                                ctx.set_contents(link.as_str().to_owned()).unwrap();
                            }
                        }
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('d'),
                modifiers: KeyModifiers::NONE,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(item) = app.items.items.get(idx) {
                        eprintln!("{:?}", item.text.text());
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('D'),
                modifiers: KeyModifiers::SHIFT,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(item) = app.items.items.get(idx) {
                        eprintln!("{:?} {:?}", item.text, item.upload_link);
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('m'),
                modifiers: KeyModifiers::NONE,
            } => {
                let mut is_muted = self.is_muted.lock().unwrap();
                *is_muted = !*is_muted;
            }
            KeyEvent {
                code: KeyCode::Char('M'),
                modifiers: KeyModifiers::SHIFT,
            } => {
                self.show_sys = !self.show_sys;
            }
            KeyEvent {
                code: KeyCode::Char('G'),
                modifiers: KeyModifiers::SHIFT,
            } => {
                self.display_guest_view = !self.display_guest_view;
            }
            KeyEvent {
                code: KeyCode::Char('H'),
                modifiers: KeyModifiers::SHIFT,
            } => {
                self.display_hidden_msgs = !self.display_hidden_msgs;
            }
            KeyEvent {
                code: KeyCode::Char('i'),
                modifiers: KeyModifiers::NONE,
            } => {
                app.input_mode = InputMode::Editing;
                app.items.unselect();
            }
            KeyEvent {
                code: KeyCode::Char('Q'),
                modifiers: KeyModifiers::SHIFT,
            } => {
                self.logout().unwrap();
                return Err(ExitSignal::Terminate);
            }
            KeyEvent {
                code: KeyCode::Char('q'),
                modifiers: KeyModifiers::NONE,
            } => {
                return Err(ExitSignal::Terminate);
            }
            KeyEvent {
                code: KeyCode::Char('t'),
                modifiers: KeyModifiers::NONE,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(username) = get_username(
                        &self.base_client.username,
                        &app.items.items.get(idx).unwrap().text,
                        &self.config.members_tag,
                    ) {
                        app.input = format!("@{} ", username);
                        app.input_idx = app.input.width();
                        app.input_mode = InputMode::Editing;
                        app.items.unselect();
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('p'),
                modifiers: KeyModifiers::NONE,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(username) = get_username(
                        &self.base_client.username,
                        &app.items.items.get(idx).unwrap().text,
                        &self.config.members_tag,
                    ) {
                        app.input = format!("/pm {} ", username);
                        app.input_idx = app.input.width();
                        app.input_mode = InputMode::Editing;
                        app.items.unselect();
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('k'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    if let Some(username) = get_username(
                        &self.base_client.username,
                        &app.items.items.get(idx).unwrap().text,
                        &self.config.members_tag,
                    ) {
                        app.input = format!("/kick {} ", username);
                        app.input_idx = app.input.width();
                        app.input_mode = InputMode::Editing;
                        app.items.unselect();
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('u'),
                modifiers: KeyModifiers::CONTROL,
            }
            | KeyEvent {
                code: KeyCode::PageUp,
                modifiers: KeyModifiers::NONE,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    app.items.state.select(idx.checked_sub(10).or(Some(0)));
                } else {
                    app.items.next();
                }
            }
            KeyEvent {
                code: KeyCode::Char('d'),
                modifiers: KeyModifiers::CONTROL,
            }
            | KeyEvent {
                code: KeyCode::PageDown,
                modifiers: KeyModifiers::NONE,
            } => {
                if let Some(idx) = app.items.state.selected() {
                    let wanted_idx = idx + 10;
                    let max_idx = app.items.items.len() - 1;
                    let new_idx = std::cmp::min(wanted_idx, max_idx);
                    app.items.state.select(Some(new_idx));
                } else {
                    app.items.next();
                }
            }
            KeyEvent {
                code: KeyCode::Esc,
                modifiers: KeyModifiers::NONE,
            } => {
                app.items.unselect();
            }
            KeyEvent {
                code: KeyCode::Char('u'),
                modifiers: KeyModifiers::SHIFT,
            } => {
                app.items.state.select(Some(0));
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_editing_mode_key_event(
        &mut self,
        app: &mut App,
        key_event: crossterm::event::KeyEvent,
        users: &Arc<Mutex<Users>>,
    ) -> std::result::Result<(), ExitSignal> {
        match key_event {
            KeyEvent {
                code: KeyCode::Enter,
                modifiers: KeyModifiers::NONE,
            } => {
                if FIND_RGX.is_match(&app.input) {
                    return Ok(());
                }

                let input: String = app.input.drain(..).collect();
                app.input_idx = 0;
                if input == "/dl" {
                    // Delete last message
                    self.post_msg(PostType::DeleteLast).unwrap();
                } else if let Some(captures) = DLX_RGX.captures(&input) {
                    // Delete the last X messages
                    let x: usize = captures.get(1).unwrap().as_str().parse().unwrap();
                    for _ in 0..x {
                        self.post_msg(PostType::DeleteLast).unwrap();
                    }
                } else if input == "/dall" {
                    // Delete all messages
                    self.post_msg(PostType::DeleteAll).unwrap();
                } else if input == "/cycles" {
                    self.color_tx.send(()).unwrap();
                } else if input == "/cycle1" {
                    self.start_cycle(true);
                } else if input == "/cycle2" {
                    self.start_cycle(false);
                } else if input == "/kall" {
                    // Kick all guests
                    let username = "s _".to_owned();
                    let msg = "".to_owned();
                    self.post_msg(PostType::Kick(msg, username)).unwrap();
                } else if input.starts_with("/m ") {
                    // Send message to "members" section
                    let msg = remove_prefix(&input, "/m ").to_owned();
                    let to = Some(SEND_TO_MEMBERS.to_owned());
                    self.post_msg(PostType::Post(msg, to)).unwrap();
                    app.input = "/m ".to_owned();
                    app.input_idx = app.input.width()
                } else if input.starts_with("/a ") {
                    // Send message to "admin" section
                    let msg = remove_prefix(&input, "/a ").to_owned();
                    let to = Some(SEND_TO_ADMINS.to_owned());
                    self.post_msg(PostType::Post(msg, to)).unwrap();
                    app.input = "/a ".to_owned();
                    app.input_idx = app.input.width()
                } else if input.starts_with("/s ") {
                    // Send message to "staff" section
                    let msg = remove_prefix(&input, "/s ").to_owned();
                    let to = Some(SEND_TO_STAFFS.to_owned());
                    self.post_msg(PostType::Post(msg, to)).unwrap();
                    app.input = "/s ".to_owned();
                    app.input_idx = app.input.width()
                } else if let Some(captures) = PM_RGX.captures(&input) {
                    // Send PM message
                    let username = &captures[1];
                    let msg = captures[2].to_owned();
                    let to = Some(username.to_owned());
                    self.post_msg(PostType::Post(msg, to)).unwrap();
                    app.input = format!("/pm {} ", username);
                    app.input_idx = app.input.width()
                } else if let Some(captures) = NEW_NICKNAME_RGX.captures(&input) {
                    // Change nickname
                    let new_nickname = captures[1].to_owned();
                    self.post_msg(PostType::NewNickname(new_nickname)).unwrap();
                } else if let Some(captures) = NEW_COLOR_RGX.captures(&input) {
                    // Change color
                    let new_color = captures[1].to_owned();
                    self.post_msg(PostType::NewColor(new_color)).unwrap();
                } else if let Some(captures) = KICK_RGX.captures(&input) {
                    // Kick a user
                    let username = captures[1].to_owned();
                    let msg = captures[2].to_owned();
                    self.post_msg(PostType::Kick(msg, username)).unwrap();
                } else if let Some(captures) = IGNORE_RGX.captures(&input) {
                    // Ignore a user
                    let username = captures[1].to_owned();
                    self.post_msg(PostType::Ignore(username)).unwrap();
                } else if let Some(captures) = UNIGNORE_RGX.captures(&input) {
                    // Unignore a user
                    let username = captures[1].to_owned();
                    self.post_msg(PostType::Unignore(username)).unwrap();
                } else if let Some(captures) = UPLOAD_RGX.captures(&input) {
                    // Upload a file
                    let file_path = captures[1].to_owned();
                    let send_to = match captures.get(2) {
                        Some(to_match) => match to_match.as_str() {
                            "members" => SEND_TO_MEMBERS,
                            "staffs" => SEND_TO_STAFFS,
                            "admins" => SEND_TO_ADMINS,
                            _ => SEND_TO_ALL,
                        },
                        None => SEND_TO_ALL,
                    }
                    .to_owned();
                    let msg = match captures.get(3) {
                        Some(msg_match) => msg_match.as_str().to_owned(),
                        None => "".to_owned(),
                    };
                    self.post_msg(PostType::Upload(file_path, send_to, msg))
                        .unwrap();
                } else {
                    // Send normal message
                    self.post_msg(PostType::Post(input, None)).unwrap();
                }
            }
            KeyEvent {
                code: KeyCode::Tab,
                modifiers: KeyModifiers::NONE,
            } => {
                let (p1, p2) = app.input.split_at(app.input_idx);
                if p2 == "" || p2.chars().nth(0) == Some(' ') {
                    let mut parts: Vec<&str> = p1.split(" ").collect();
                    if let Some(user_prefix) = parts.pop() {
                        let mut should_autocomplete = false;
                        let mut prefix = "";
                        if parts.len() == 1
                            && ((parts[0] == "/kick" || parts[0] == "/k" || parts[0] == "/pm")
                                || parts[0] == "/ignore"
                                || parts[0] == "/unignore")
                        {
                            should_autocomplete = true;
                        } else if user_prefix.starts_with("@") {
                            should_autocomplete = true;
                            prefix = "@";
                        }
                        if should_autocomplete {
                            let user_prefix_norm = remove_prefix(user_prefix, prefix);
                            let user_prefix_norm_len = user_prefix_norm.len();
                            if let Some(name) = autocomplete_username(users, user_prefix_norm) {
                                let complete_name = format!("{}{}", prefix, name);
                                parts.push(complete_name.as_str());
                                let p2 = p2.trim_start();
                                if p2 != "" {
                                    parts.push(p2);
                                }
                                app.input = parts.join(" ");
                                app.input_idx += name.len() - user_prefix_norm_len;
                            }
                        }
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                app.clear_filter();
                app.input = "".to_owned();
                app.input_idx = 0;
                app.input_mode = InputMode::Normal;
            }
            KeyEvent {
                code: KeyCode::Char('a'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                app.input_idx = 0;
            }
            KeyEvent {
                code: KeyCode::Char('e'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                app.input_idx = app.input.width();
            }
            KeyEvent {
                code: KeyCode::Char('f'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                if let Some(idx) = app.input.chars().skip(app.input_idx).position(|c| c == ' ') {
                    app.input_idx = std::cmp::min(app.input_idx + idx + 1, app.input.width());
                } else {
                    app.input_idx = app.input.width();
                }
            }
            KeyEvent {
                code: KeyCode::Char('b'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                if let Some(idx) = app.input_idx.checked_sub(2) {
                    let tmp = app
                        .input
                        .chars()
                        .take(idx)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect::<String>();
                    if let Some(idx) = tmp.chars().position(|c| c == ' ') {
                        app.input_idx = std::cmp::max(tmp.width() - idx, 0);
                    } else {
                        app.input_idx = 0;
                    }
                }
            }
            KeyEvent {
                code: KeyCode::Char('v'),
                modifiers: KeyModifiers::CONTROL,
            } => {
                let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                if let Ok(clipboard) = ctx.get_contents() {
                    let byte_position = byte_pos(&app.input, app.input_idx).unwrap();
                    app.input.insert_str(byte_position, &clipboard);
                    app.input_idx += clipboard.width();
                }
            }
            KeyEvent {
                code: KeyCode::Left,
                modifiers: KeyModifiers::NONE,
            } => {
                if app.input_idx > 0 {
                    app.input_idx -= 1;
                }
            }
            KeyEvent {
                code: KeyCode::Right,
                modifiers: KeyModifiers::NONE,
            } => {
                if app.input_idx < app.input.width() {
                    app.input_idx += 1;
                }
            }
            KeyEvent {
                code: KeyCode::Down,
                modifiers: KeyModifiers::NONE,
            } => {
                app.input_mode = InputMode::Normal;
                app.items.next();
            }
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers: KeyModifiers::NONE,
            }
            | KeyEvent {
                code: KeyCode::Char(c),
                modifiers: KeyModifiers::SHIFT,
            } => {
                let byte_position = byte_pos(&app.input, app.input_idx).unwrap();
                app.input.insert(byte_position, c);

                app.input_idx += 1;
                app.update_filter();
            }
            KeyEvent {
                code: KeyCode::Backspace,
                modifiers: KeyModifiers::NONE,
            } => {
                if app.input_idx > 0 {
                    app.input_idx -= 1;
                    app.input = remove_at(&app.input, app.input_idx);
                    app.update_filter();
                }
            }
            KeyEvent {
                code: KeyCode::Delete,
                modifiers: KeyModifiers::NONE,
            } => {
                if app.input_idx > 0 && app.input_idx == app.input.width() {
                    app.input_idx -= 1;
                }
                app.input = remove_at(&app.input, app.input_idx);
                app.update_filter();
            }
            KeyEvent {
                code: KeyCode::Esc,
                modifiers: KeyModifiers::NONE,
            } => {
                app.input_mode = InputMode::Normal;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_mouse_event(
        &mut self,
        app: &mut App,
        mouse_event: MouseEvent,
    ) -> std::result::Result<(), ExitSignal> {
        match mouse_event.kind {
            MouseEventKind::ScrollDown => app.items.next(),
            MouseEventKind::ScrollUp => app.items.previous(),
            _ => {}
        }
        Ok(())
    }
}

// Give a char index, return the byte position
fn byte_pos(v: &str, idx: usize) -> Option<usize> {
    let mut b = 0;
    let mut chars = v.chars();
    for _ in 0..idx {
        if let Some(c) = chars.next() {
            b += c.len_utf8();
        } else {
            return None;
        }
    }
    Some(b)
}

// Remove the character at idx (utf-8 aware)
fn remove_at(v: &str, idx: usize) -> String {
    v.chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i == idx {
                return None;
            }
            Some(c)
        })
        .collect::<String>()
}

// Autocomplete any username
fn autocomplete_username(users: &Arc<Mutex<Users>>, prefix: &str) -> Option<String> {
    let users = users.lock().unwrap();
    let all_users = users.all();
    let mut filtered = all_users.iter().find(|(_, name)| name.starts_with(prefix));
    if filtered.is_none() {
        let prefix_lower = prefix.to_lowercase();
        filtered = all_users
            .iter()
            .find(|(_, name)| name.to_lowercase().starts_with(&prefix_lower));
    }
    match filtered {
        Some((_, name)) => Some(name.to_owned()),
        None => None,
    }
}

fn set_profile_base_info(
    client: &Client,
    full_url: &str,
    params: &mut Vec<(&str, String)>,
) -> Result<()> {
    params.extend(vec![("action", "profile".to_owned())]);
    let profile_resp = client.post(full_url).form(&params).send()?;
    let profile_resp_txt = profile_resp.text().unwrap();
    let doc = Document::from(profile_resp_txt.as_str());
    let bold = doc.select(Attr("id", "bold")).next().unwrap();
    let italic = doc.select(Attr("id", "italic")).next().unwrap();
    let small = doc.select(Attr("id", "small")).next().unwrap();
    if let Some(_) = bold.attr("checked") {
        params.push(("bold", "on".to_owned()));
    }
    if let Some(_) = italic.attr("checked") {
        params.push(("italic", "on".to_owned()));
    }
    if let Some(_) = small.attr("checked") {
        params.push(("small", "on".to_owned()));
    }
    let font_select = doc.select(Attr("name", "font")).next().unwrap();
    let font = font_select.select(Name("option")).find_map(|el| {
        if let Some(_) = el.attr("selected") {
            return Some(el.attr("value").unwrap());
        }
        None
    });
    params.push(("font", font.unwrap_or("").to_owned()));
    Ok(())
}

fn delete_message(
    client: &Client,
    full_url: &str,
    params: &mut Vec<(&str, String)>,
    date: String,
    text: String,
) -> Result<()> {
    params.extend(vec![
        ("action", "admin".to_owned()),
        ("do", "clean".to_owned()),
        ("what", "choose".to_owned()),
    ]);
    let clean_resp = client.post(full_url).form(&params).send()?;
    let clean_resp_txt = clean_resp.text().unwrap();
    let doc = Document::from(clean_resp_txt.as_str());
    let nc = doc.select(Attr("name", "nc")).next().unwrap();
    let nc_value = nc.attr("value").unwrap().to_owned();
    let msgs = extract_messages(&doc).unwrap();
    if let Some(msg) = msgs
        .iter()
        .find(|m| m.date == date && m.text.text() == text)
    {
        params.extend(vec![
            ("nc", nc_value.to_owned()),
            ("what", "selected".to_owned()),
            ("mid[]", format!("{}", msg.id.unwrap())),
        ]);
        client.post(full_url).form(&params).send()?;
    }
    Ok(())
}

fn ban_imposters(tx: &crossbeam_channel::Sender<PostType>, account_username: &str, users: &Users) {
    if BAN_IMPOSTERS {
        if users.admin.len() == 0 && (users.staff.len() == 0 || account_username == N0TR1V) {
            let n0tr1v_rgx = Regex::new(r#"n[o|0]tr[1|i|l][v|y]"#).unwrap(); // o 0 | 1 i l | v y
            let molester_rgx = Regex::new(r#"m[o|0][1|l][e|3][s|5|$]t[e|3]r"#).unwrap();
            let rapist_rgx = Regex::new(r#"r[a|4]p[i|1|l]st"#).unwrap();
            let hitler_rgx = Regex::new(r#"h[i|1|l]t[l|1]er"#).unwrap();
            let himmler_rgx = Regex::new(r#"h[i|1]m+l[e|3]r"#).unwrap();
            let goebbels_rgx = Regex::new(r#"g[o|0][e|3]b+[e|3]ls"#).unwrap();
            let heydrich_rgx = Regex::new(r#"h[e|3]ydr[i|1]ch"#).unwrap();
            let globocnik_rgx = Regex::new(r#"gl[o|0]b[o|0]cn[i|1|l]k"#).unwrap();
            let dirlewanger_rgx = Regex::new(r#"d[i|1]rl[e|3]wang[e|3]r"#).unwrap();
            let jeckeln_rgx = Regex::new(r#"j[e|3]ck[e|3]ln"#).unwrap();
            let kramer_rgx = Regex::new(r#"kram[e|3]r"#).unwrap();
            let blobel_rgx = Regex::new(r#"bl[o|0]b[e|3]l"#).unwrap();
            let stangl_rgx = Regex::new(r#"stangl"#).unwrap();
            for (_color, username) in &users.guests {
                let lower_name = username.to_lowercase();
                // Names that anyone using bhcli will ban
                if n0tr1v_rgx.is_match(&lower_name) || lower_name.contains("pedo") {
                    let msg = "forbidden name".to_owned();
                    let username = username.to_owned();
                    tx.send(PostType::Kick(msg, username)).unwrap();
                }
                // Names that only "n0tr1v" will ban
                if account_username == N0TR1V {
                    if lower_name.contains("fuck")
                        || lower_name.contains("nigger")
                        || lower_name.contains("nigga")
                        || lower_name.contains("chink")
                        || lower_name.contains("atomwaffen")
                        || lower_name.contains("altright")
                        || hitler_rgx.is_match(&lower_name)
                        || goebbels_rgx.is_match(&lower_name)
                        || himmler_rgx.is_match(&lower_name)
                        || heydrich_rgx.is_match(&lower_name)
                        || globocnik_rgx.is_match(&lower_name)
                        || dirlewanger_rgx.is_match(&lower_name)
                        || jeckeln_rgx.is_match(&lower_name)
                        || kramer_rgx.is_match(&lower_name)
                        || blobel_rgx.is_match(&lower_name)
                        || stangl_rgx.is_match(&lower_name)
                        || rapist_rgx.is_match(&lower_name)
                        || molester_rgx.is_match(&lower_name)
                    {
                        let msg = "forbidden name".to_owned();
                        let username = username.to_owned();
                        tx.send(PostType::Kick(msg, username)).unwrap();
                    }
                }
            }
        }
    }
}

struct CustomClient<'a> {
    le_chat_php_client: LeChatPHPClient<'a>,
}

impl ChatClient for CustomClient<'_> {
    fn run_forever(&mut self) {
        self.le_chat_php_client.run_forever();
    }
}

impl<'a> CustomClient<'a> {
    fn new(params: Params<'a>) -> Self {
        let mut c = new_default_le_chat_php_client(params.clone());
        c.config.url = params.url.unwrap_or("".to_owned());
        c.config.page_php = params.page_php.unwrap_or("chat.php".to_owned());
        c.config.datetime_fmt = params.datetime_fmt.unwrap_or("%m-%d %H:%M:%S".to_owned());
        c.config.members_tag = params.members_tag.unwrap_or("[M] ".to_owned());
        c.config.keepalive_send_to = None;
        Self {
            le_chat_php_client: c,
        }
    }
}

struct BHClient<'a> {
    le_chat_php_client: LeChatPHPClient<'a>,
}

impl ChatClient for BHClient<'_> {
    fn run_forever(&mut self) {
        self.le_chat_php_client.run_forever();
    }
}

fn new_default_le_chat_php_client(params: Params) -> LeChatPHPClient {
    let (color_tx, color_rx) = crossbeam_channel::unbounded();
    let (tx, rx) = crossbeam_channel::unbounded();
    LeChatPHPClient {
        base_client: BaseClient {
            username: params.username,
            password: params.password,
        },
        max_login_retry: params.max_login_retry,
        guest_color: params.guest_color,
        session: "".to_owned(),
        client: params.client,
        dkf_api_key: params.dkf_api_key,
        manual_captcha: params.manual_captcha,
        refresh_rate: params.refresh_rate,
        config: LeChatPHPConfig::new_black_hat_chat_config(),
        is_muted: Arc::new(Mutex::new(false)),
        show_sys: false,
        display_guest_view: false,
        display_hidden_msgs: false,
        tx,
        rx: Arc::new(Mutex::new(rx)),
        color_tx,
        color_rx: Arc::new(Mutex::new(color_rx)),
    }
}

impl<'a> BHClient<'a> {
    fn new(params: Params<'a>) -> Self {
        let mut c = new_default_le_chat_php_client(params);
        c.config = LeChatPHPConfig::new_black_hat_chat_config();
        c.manual_captcha = true;
        Self {
            le_chat_php_client: c,
        }
    }
}

trait ChatClient {
    fn run_forever(&mut self);
}

struct DanClient<'a> {
    le_chat_php_client: LeChatPHPClient<'a>,
}

impl ChatClient for DanClient<'_> {
    fn run_forever(&mut self) {
        self.le_chat_php_client.run_forever();
    }
}

impl<'a> DanClient<'a> {
    fn new(params: Params<'a>) -> Self {
        let mut c = new_default_le_chat_php_client(params);
        c.config = LeChatPHPConfig::new_dans_chat_config();
        c.manual_captcha = true;
        Self {
            le_chat_php_client: c,
        }
    }
}

#[derive(Debug, Clone)]
struct Params<'a> {
    url: Option<String>,
    page_php: Option<String>,
    datetime_fmt: Option<String>,
    members_tag: Option<String>,
    username: String,
    password: String,
    guest_color: String,
    client: &'a Client,
    dkf_api_key: Option<String>,
    manual_captcha: bool,
    refresh_rate: u64,
    max_login_retry: isize,
}

#[derive(Clone)]
enum ExitSignal {
    Terminate,
    NeedLogin,
}
struct Sig {
    tx: crossbeam_channel::Sender<ExitSignal>,
    rx: crossbeam_channel::Receiver<ExitSignal>,
    nb_rx: usize,
}

impl Sig {
    fn new() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let nb_rx = 0;
        Self { tx, rx, nb_rx }
    }

    fn clone(&mut self) -> crossbeam_channel::Receiver<ExitSignal> {
        self.nb_rx += 1;
        self.rx.clone()
    }

    fn signal(&self, signal: ExitSignal) {
        for _ in 0..self.nb_rx {
            self.tx.send(signal.clone()).unwrap();
        }
    }
}

fn trim_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

fn get_guest_color(wanted: Option<String>) -> String {
    match wanted.as_deref() {
        Some("beige") => "F5F5DC",
        Some("blue-violet") => "8A2BE2",
        Some("brown") => "A52A2A",
        Some("cyan") => "00FFFF",
        Some("sky-blue") => "00BFFF",
        Some("gold") => "FFD700",
        Some("gray") => "808080",
        Some("green") => "008000",
        Some("hot-pink") => "FF69B4",
        Some("light-blue") => "ADD8E6",
        Some("light-green") => "90EE90",
        Some("lime-green") => "32CD32",
        Some("magenta") => "FF00FF",
        Some("olive") => "808000",
        Some("orange") => "FFA500",
        Some("orange-red") => "FF4500",
        Some("red") => "FF0000",
        Some("royal-blue") => "4169E1",
        Some("see-green") => "2E8B57",
        Some("sienna") => "A0522D",
        Some("silver") => "C0C0C0",
        Some("tan") => "D2B48C",
        Some("teal") => "008080",
        Some("violet") => "EE82EE",
        Some("white") => "FFFFFF",
        Some("yellow") => "FFFF00",
        Some("yellow-green") => "9ACD32",
        Some(other) => COLOR1_RGX
            .captures(other)
            .map_or("", |captures| captures.get(1).map_or("", |m| m.as_str())),
        None => "",
    }
    .to_owned()
}

fn get_tor_client(socks_proxy_url: &str) -> Client {
    // Create client
    let mut builder = reqwest::blocking::ClientBuilder::new()
        .cookie_store(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0");

    if socks_proxy_url != "" {
        let proxy = match reqwest::Proxy::all(socks_proxy_url) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        };
        builder = builder.proxy(proxy);
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };
    client
}

fn ask_username(username: Option<String>) -> String {
    match username {
        Some(u) => u,
        None => {
            print!("username: ");
            let mut username_input = String::new();
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut username_input).unwrap();
            trim_newline(&mut username_input);
            username_input
        }
    }
}

fn ask_password(password: Option<String>) -> String {
    match password {
        Some(p) => p,
        None => rpassword::prompt_password_stdout("Password: ").unwrap(),
    }
}

enum ClientType {
    BHC,
    Dan,
    Custom,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DkfNotifierResp {
    #[serde(rename = "NewMessageSound")]
    pub new_message_sound: bool,
    #[serde(rename = "TaggedSound")]
    pub tagged_sound: bool,
    #[serde(rename = "PmSound")]
    pub pm_sound: bool,
    #[serde(rename = "InboxCount")]
    pub inbox_count: i64,
    #[serde(rename = "LastMessageCreatedAt")]
    pub last_message_created_at: String,
}

fn start_dkf_notifier(client: &Client, dkf_api_key: &str) {
    let client = client.clone();
    let dkf_api_key = dkf_api_key.to_owned();
    let mut last_known_date = chrono::offset::Utc::now();
    thread::spawn(move || loop {
        let (_stream, stream_handle) = OutputStream::try_default().unwrap();
        let source = Decoder::new_mp3(Cursor::new(SOUND1)).unwrap();

        let params: Vec<(&str, String)> = vec![(
            "last_known_date",
            last_known_date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )];
        let right_url = format!("{}/api/v1/chat/1/notifier", DKF_URL);
        if let Ok(resp) = client
            .post(right_url)
            .form(&params)
            .header("DKF_API_KEY", &dkf_api_key)
            .send()
        {
            if let Ok(txt) = resp.text() {
                if let Ok(v) = serde_json::from_str::<DkfNotifierResp>(&txt) {
                    if v.pm_sound || v.tagged_sound {
                        stream_handle.play_raw(source.convert_samples()).unwrap();
                    }
                    last_known_date = DateTime::parse_from_rfc3339(&v.last_message_created_at)
                        .unwrap()
                        .with_timezone(&Utc);
                }
            }
        }
        thread::sleep(time::Duration::from_secs(5));
    });
}

// Start thread that looks for new emails on DNMX every minutes.
fn start_dnmx_mail_notifier(client: &Client, username: &str, password: &str) {
    let params: Vec<(&str, &str)> = vec![("login_username", username), ("secretkey", password)];
    let login_url = format!("{}/src/redirect.php", DNMX_URL);
    client.post(login_url).form(&params).send().unwrap();

    let client_clone = client.clone();
    thread::spawn(move || loop {
        let (_stream, stream_handle) = OutputStream::try_default().unwrap();
        let source = Decoder::new_mp3(Cursor::new(SOUND1)).unwrap();

        let right_url = format!("{}/src/right_main.php", DNMX_URL);
        if let Ok(resp) = client_clone.get(right_url).send() {
            let mut nb_mails = 0;
            let doc = Document::from(resp.text().unwrap().as_str());
            if let Some(table) = doc.select(Name("table")).nth(7) {
                table.select(Name("tr")).skip(1).for_each(|n| {
                    if let Some(td) = n.select(Name("td")).nth(2) {
                        if let Some(_) = td.select(Name("b")).nth(0) {
                            nb_mails += 1;
                        }
                    }
                });
            }
            if nb_mails > 0 {
                eprintln!("{} new mails", nb_mails);
                stream_handle.play_raw(source.convert_samples()).unwrap();
            }
        }
        thread::sleep(time::Duration::from_secs(60));
    });
}

fn main() -> Result<()> {
    let mut opts: Opts = Opts::parse();

    // Configs file
    let cfg: MyConfig = confy::load("bhcli")?;
    if opts.dkf_api_key.is_none() {
        opts.dkf_api_key = cfg.dkf_api_key;
    }
    if let Some(default_profile) = cfg.profiles.get(&opts.profile) {
        if opts.username.is_none() {
            opts.username = Some(default_profile.username.clone());
            opts.password = Some(default_profile.password.clone());
        }
    }

    let client = get_tor_client(&opts.socks_proxy_url);

    // If dnmx username is set, start mail notifier thread
    if let Some(dnmx_username) = opts.dnmx_username {
        start_dnmx_mail_notifier(&client, &dnmx_username, &opts.dnmx_password.unwrap())
    }

    if let Some(dkf_api_key) = &opts.dkf_api_key {
        start_dkf_notifier(&client, dkf_api_key);
    }

    let guest_color = get_guest_color(opts.guest_color);
    let username = ask_username(opts.username);
    let password = ask_password(opts.password);
    let params = Params {
        url: opts.url,
        page_php: opts.page_php,
        datetime_fmt: opts.datetime_fmt,
        members_tag: opts.members_tag,
        username,
        password,
        guest_color,
        client: &client,
        dkf_api_key: opts.dkf_api_key,
        manual_captcha: opts.manual_captcha,
        refresh_rate: opts.refresh_rate,
        max_login_retry: opts.max_login_retry,
    };

    let chat_type = if params.url.is_some() {
        ClientType::Custom
    } else if opts.dan {
        ClientType::Dan
    } else {
        ClientType::BHC
    };

    let mut chat_client: Box<dyn ChatClient> = match chat_type {
        ClientType::Custom => Box::new(CustomClient::new(params)),
        ClientType::BHC => Box::new(BHClient::new(params)),
        ClientType::Dan => Box::new(DanClient::new(params)),
    };
    chat_client.run_forever();

    Ok(())
}

#[derive(Debug, Clone)]
enum PostType {
    Post(String, Option<String>),   // Message, SendTo
    Kick(String, String),           // Message, Username
    Upload(String, String, String), // FilePath, SendTo, Message
    DeleteLast,                     // DeleteLast
    DeleteAll,                      // DeleteAll
    NewNickname(String),            // NewUsername
    NewColor(String),               // NewColor
    Profile(String, String),        // NewColor, NewUsername
    Ignore(String),                 // Username
    Unignore(String),               // Username
    Clean(String, String),          // Clean message
}

// Get username of other user (or ours if it's the only one)
fn get_username(own_username: &str, root: &StyledText, members_tag: &str) -> Option<String> {
    match get_message(root, members_tag) {
        Some((from, Some(to), _)) => {
            if from == own_username {
                return Some(to);
            }
            return Some(from);
        }
        Some((from, None, _)) => {
            return Some(from);
        }
        _ => return None,
    }
}

// Extract "from"/"to"/"message content" from a "StyledText"
fn get_message(root: &StyledText, members_tag: &str) -> Option<(String, Option<String>, String)> {
    if let StyledText::Styled(_, children) = root {
        let msg = match children.get(0) {
            Some(el) => el.text(),
            _ => return None,
        };
        if let Some(StyledText::Styled(_, children)) = children.get(children.len() - 1) {
            let from = match children.get(children.len() - 1) {
                Some(StyledText::Text(t)) => t.to_owned(),
                _ => return None,
            };
            return Some((from, None, msg));
        } else if let Some(StyledText::Text(t)) = children.get(children.len() - 1) {
            if t == &members_tag {
                let from = match children.get(children.len() - 2) {
                    Some(StyledText::Styled(_, children)) => match children.get(children.len() - 1)
                    {
                        Some(StyledText::Text(t)) => t.to_owned(),
                        _ => return None,
                    },
                    _ => return None,
                };
                return Some((from, None, msg));
            } else if t == "[" {
                let from = match children.get(children.len() - 2) {
                    Some(StyledText::Styled(_, children)) => match children.get(children.len() - 1)
                    {
                        Some(StyledText::Text(t)) => t.to_owned(),
                        _ => return None,
                    },
                    _ => return None,
                };
                let to = match children.get(2) {
                    Some(StyledText::Styled(_, children)) => match children.get(children.len() - 1)
                    {
                        Some(StyledText::Text(t)) => Some(t.to_owned()),
                        _ => return None,
                    },
                    _ => return None,
                };
                return Some((from, to, msg));
            }
        }
    }
    return None;
}

#[derive(Debug, PartialEq, Clone)]
enum MessageType {
    UserMsg,
    SysMsg,
}

#[derive(Debug, PartialEq, Clone)]
struct Message {
    id: Option<usize>,
    typ: MessageType,
    date: String,
    upload_link: Option<String>,
    text: StyledText,
    deleted: bool, // Either or not a message was deleted on the chat
    hide: bool,    // Either ot not to hide a specific message
}

#[derive(Debug, PartialEq, Clone)]
enum StyledText {
    Styled(tuiColor, Vec<StyledText>),
    Text(String),
    None,
}

impl StyledText {
    fn walk<F>(&self, mut clb: F)
    where
        F: FnMut(StyledText),
    {
        let mut v: Vec<&StyledText> = vec![self];
        loop {
            if let Some(e) = v.pop() {
                clb(e.clone());
                if let StyledText::Styled(_, children) = e {
                    v.extend(children);
                }
                continue;
            }
            break;
        }
    }

    fn text(&self) -> String {
        let mut s = String::new();
        self.walk(|n| {
            if let StyledText::Text(t) = n {
                s += &t;
            }
        });
        s
    }

    // Return a vector of each text parts & what color it should be
    fn colored_text(&self) -> Vec<(tuiColor, String)> {
        let mut out: Vec<(tuiColor, String)> = vec![];
        let mut v: Vec<(tuiColor, &StyledText)> = vec![(tuiColor::White, self)];
        loop {
            if let Some((el_color, e)) = v.pop() {
                match e {
                    StyledText::Styled(tui_color, children) => {
                        for child in children {
                            v.push((*tui_color, child));
                        }
                    }
                    StyledText::Text(t) => {
                        out.push((el_color, t.to_owned()));
                    }
                    StyledText::None => {}
                }
                continue;
            }
            break;
        }
        out
    }
}

fn parse_color(color_str: &str) -> tuiColor {
    let mut color = tuiColor::White;
    if color_str == "red" {
        return tuiColor::Red;
    }
    if let Ok(rgb) = Rgb::from_hex_str(color_str) {
        color = tuiColor::Rgb(
            rgb.get_red() as u8,
            rgb.get_green() as u8,
            rgb.get_blue() as u8,
        );
    }
    color
}

fn process_node(e: select::node::Node, mut color: tuiColor) -> (StyledText, Option<String>) {
    match e.data() {
        select::node::Data::Element(_, _) => {
            let mut upload_link: Option<String> = None;
            if e.name() == Some("span") {
                if let Some(style) = e.attr("style") {
                    if let Some(captures) = COLOR_RGX.captures(style) {
                        let color_match = captures.get(1).unwrap().as_str();
                        color = parse_color(color_match);
                    }
                }
            } else if e.name() == Some("font") {
                if let Some(color_str) = e.attr("color") {
                    color = parse_color(color_str);
                }
            } else if e.name() == Some("a") {
                color = tuiColor::White;
                if let Some(class) = e.attr("class") {
                    if class == "attachement" {
                        if let Some(ahref) = e.attr("href") {
                            upload_link = Some(ahref.to_owned());
                        }
                    }
                }
            }
            let mut children_texts: Vec<StyledText> = vec![];
            let children = e.children();
            for child in children {
                let (st, ul) = process_node(child, color);
                if let Some(_) = &ul {
                    upload_link = ul;
                }
                children_texts.push(st);
            }
            children_texts.reverse();
            (StyledText::Styled(color, children_texts), upload_link)
        }
        select::node::Data::Text(t) => (StyledText::Text(t.to_string()), None),
        select::node::Data::Comment(_) => (StyledText::None, None),
    }
}

struct Users {
    admin: Vec<(tuiColor, String)>,
    staff: Vec<(tuiColor, String)>,
    members: Vec<(tuiColor, String)>,
    guests: Vec<(tuiColor, String)>,
}

impl Default for Users {
    fn default() -> Self {
        Self {
            admin: Default::default(),
            staff: Default::default(),
            members: Default::default(),
            guests: Default::default(),
        }
    }
}

impl Users {
    fn all(&self) -> Vec<&(tuiColor, String)> {
        let mut out = Vec::new();
        out.extend(&self.admin);
        out.extend(&self.staff);
        out.extend(&self.members);
        out.extend(&self.guests);
        out
    }
}

fn extract_users(doc: &Document) -> Users {
    let mut admin = Vec::new();
    let mut staff = Vec::new();
    let mut members = Vec::new();
    let mut guests = Vec::new();

    if let Some(chatters) = doc.select(Attr("id", "chatters")).next() {
        if let Some(tr) = chatters.select(Name("tr")).next() {
            let mut th_count = 0;
            for e in tr.children() {
                if let select::node::Data::Element(_, _) = e.data() {
                    if e.name() == Some("th") {
                        th_count += 1;
                        continue;
                    }
                    for user_span in e.select(Name("span")) {
                        if let Some(user_style) = user_span.attr("style") {
                            if let Some(captures) = COLOR_RGX.captures(user_style) {
                                if let Some(color_match) = captures.get(1) {
                                    let color = color_match.as_str().to_owned();
                                    let tui_color = parse_color(&color);
                                    let username = user_span.text();
                                    match th_count {
                                        1 => admin.push((tui_color, username)),
                                        2 => staff.push((tui_color, username)),
                                        3 => members.push((tui_color, username)),
                                        4 => guests.push((tui_color, username)),
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Users {
        admin,
        staff,
        members,
        guests,
    }
}

fn remove_suffix<'a>(s: &'a str, suffix: &str) -> &'a str {
    match s.strip_suffix(suffix) {
        Some(s) => s,
        None => s,
    }
}

fn remove_prefix<'a>(s: &'a str, prefix: &str) -> &'a str {
    match s.strip_prefix(prefix) {
        Some(s) => s,
        None => s,
    }
}

fn extract_messages(doc: &Document) -> Result<Vec<Message>> {
    let msgs = doc
        .select(Attr("id", "messages"))
        .next()
        .ok_or("failed to get messages div")?
        .select(Attr("class", "msg"))
        .filter_map(|tag| {
            let mut id: Option<usize> = None;
            if let Some(checkbox) = tag.select(Name("input")).next() {
                let id_value: usize = checkbox.attr("value").unwrap().parse().unwrap();
                id = Some(id_value);
            }
            if let Some(date_node) = tag.select(Name("small")).next() {
                if let Some(msg_span) = tag.select(Name("span")).next() {
                    let date = remove_suffix(&date_node.text(), " - ").to_owned();
                    let typ = match msg_span.attr("class") {
                        Some("usermsg") => MessageType::UserMsg,
                        Some("sysmsg") => MessageType::SysMsg,
                        _ => return None,
                    };
                    let (text, upload_link) = process_node(msg_span, tuiColor::White);
                    return Some(Message {
                        id,
                        typ,
                        date,
                        upload_link,
                        text,
                        deleted: false,
                        hide: false,
                    });
                }
            }
            None
        })
        .collect::<Vec<_>>();
    Ok(msgs)
}

fn draw_terminal_frame(
    f: &mut Frame<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    messages: &Arc<Mutex<Vec<Message>>>,
    users: &Arc<Mutex<Users>>,
) {
    if app.long_message.is_none() {
        let hchunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(1), Constraint::Length(25)].as_ref())
            .split(f.size());

        {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(
                    [
                        Constraint::Length(1),
                        Constraint::Length(3),
                        Constraint::Min(1),
                    ]
                    .as_ref(),
                )
                .split(hchunks[0]);

            render_help_txt(f, app, chunks[0]);
            render_textbox(f, app, chunks[1]);
            render_messages(f, app, chunks[2], messages);
            render_users(f, hchunks[1], users);
        }
    } else {
        let hchunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(1)])
            .split(f.size());
        {
            render_long_message(f, app, hchunks[0]);
        }
    }
}

fn gen_lines(msg_txt: &StyledText, w: usize, line_prefix: String) -> Vec<Vec<(tuiColor, String)>> {
    let txt = msg_txt.text();
    let wrapped = textwrap::fill(&txt, w);
    let splits = wrapped.split("\n").collect::<Vec<&str>>();
    let mut new_lines: Vec<Vec<(tuiColor, String)>> = Vec::new();
    let mut ctxt = msg_txt.colored_text();
    ctxt.reverse();
    let mut ptr = 0;
    let mut split_idx = 0;
    let mut line: Vec<(tuiColor, String)> = Vec::new();
    let mut first_in_line = true;
    loop {
        if let Some((color, mut txt)) = ctxt.pop() {
            txt = txt.replace("\n", "");
            if let Some(split) = splits.get(split_idx) {
                if let Some(chr) = txt.chars().next() {
                    if chr == ' ' && first_in_line {
                        let skipped: String = txt.chars().skip(1).collect();
                        txt = skipped;
                    }
                }

                let txt = txt.as_str();

                let remain = split.len() - ptr;
                if txt.len() <= remain {
                    ptr += txt.len();
                    line.push((color, txt.to_owned()));
                    first_in_line = false;
                } else {
                    line.push((color, txt[0..remain].to_owned()));
                    new_lines.push(line.clone());
                    line.clear();
                    line.push((tuiColor::White, line_prefix.clone()));
                    ctxt.push((color, txt[(remain)..].to_owned()));
                    ptr = 0;
                    split_idx += 1;
                    first_in_line = true;
                }
            }
        } else {
            new_lines.push(line.clone());
            break;
        }
    }
    new_lines
}

fn render_long_message(f: &mut Frame<CrosstermBackend<io::Stdout>>, app: &mut App, r: Rect) {
    if let Some(m) = &app.long_message {
        let new_lines = gen_lines(&m.text, (r.width - 2) as usize, "".to_owned());

        let mut rows = vec![];
        let mut spans_vec = vec![];
        for line in new_lines.into_iter() {
            for (color, txt) in line {
                spans_vec.push(Span::styled(txt, Style::default().fg(color)));
            }
            rows.push(Spans::from(spans_vec.clone()));
            spans_vec.clear();
        }

        let messages_list_items = vec![ListItem::new(rows)];

        let messages_list = List::new(messages_list_items)
            .block(Block::default().borders(Borders::ALL).title(""))
            .highlight_style(
                Style::default()
                    .bg(tuiColor::Rgb(50, 50, 50))
                    .add_modifier(Modifier::BOLD),
            );

        f.render_widget(messages_list, r);
    }
}

fn render_help_txt(f: &mut Frame<CrosstermBackend<io::Stdout>>, app: &mut App, r: Rect) {
    let (mut msg, style) = match app.input_mode {
        InputMode::Normal => (
            vec![
                Span::raw("Press "),
                Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to exit, "),
                Span::styled("i", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to start editing."),
            ],
            Style::default(),
        ),
        InputMode::Editing => (
            vec![
                Span::raw("Press "),
                Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to stop editing, "),
                Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" to record the message"),
            ],
            Style::default(),
        ),
        InputMode::LongMessage => (vec![], Style::default()),
    };
    if app.is_muted {
        let fg = tuiColor::Red;
        let style = Style::default().fg(fg).add_modifier(Modifier::BOLD);
        msg.extend(vec![Span::raw(" | "), Span::styled("muted", style)]);
    } else {
        let fg = tuiColor::LightGreen;
        let style = Style::default().fg(fg).add_modifier(Modifier::BOLD);
        msg.extend(vec![Span::raw(" | "), Span::styled("not muted", style)]);
    }
    if app.display_guest_view {
        let fg = tuiColor::LightGreen;
        let style = Style::default().fg(fg).add_modifier(Modifier::BOLD);
        msg.extend(vec![Span::raw(" | "), Span::styled("G", style)]);
    } else {
        let fg = tuiColor::Gray;
        let style = Style::default().fg(fg);
        msg.extend(vec![Span::raw(" | "), Span::styled("G", style)]);
    }
    if app.display_hidden_msgs {
        let fg = tuiColor::LightGreen;
        let style = Style::default().fg(fg).add_modifier(Modifier::BOLD);
        msg.extend(vec![Span::raw(" | "), Span::styled("H", style)]);
    } else {
        let fg = tuiColor::Gray;
        let style = Style::default().fg(fg);
        msg.extend(vec![Span::raw(" | "), Span::styled("H", style)]);
    }
    let mut text = Text::from(Spans::from(msg));
    text.patch_style(style);
    let help_message = Paragraph::new(text);
    f.render_widget(help_message, r);
}

fn render_textbox(f: &mut Frame<CrosstermBackend<io::Stdout>>, app: &mut App, r: Rect) {
    let w = (r.width - 3) as usize;
    let str = app.input.clone();
    let mut input_str = str.as_str();
    let mut overflow = 0;
    if app.input_idx >= w {
        overflow = std::cmp::max(app.input.width() - w, 0);
        input_str = &str[overflow..];
    }
    let input = Paragraph::new(input_str)
        .style(match app.input_mode {
            InputMode::LongMessage => Style::default(),
            InputMode::Normal => Style::default(),
            InputMode::Editing => Style::default().fg(tuiColor::Yellow),
        })
        .block(Block::default().borders(Borders::ALL).title("Input"));
    f.render_widget(input, r);
    match app.input_mode {
        InputMode::LongMessage => {}
        InputMode::Normal =>
            // Hide the cursor. `Frame` does this by default, so we don't need to do anything here
            {}

        InputMode::Editing => {
            // Make the cursor visible and ask tui-rs to put it at the specified coordinates after rendering
            f.set_cursor(
                // Put cursor past the end of the input text
                r.x + app.input_idx as u16 - overflow as u16 + 1,
                // Move one line down, from the border to the input line
                r.y + 1,
            )
        }
    }
}

fn render_messages(
    f: &mut Frame<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    r: Rect,
    messages: &Arc<Mutex<Vec<Message>>>,
) {
    // Messages
    app.items.items.clear();
    let messages = messages.lock().unwrap();
    let messages_list_items: Vec<ListItem> = messages
        .iter()
        .filter_map(|m| {
            if !app.display_hidden_msgs && m.hide {
                return None;
            }
            // Simulate a guest view (remove "PMs" and "Members chat" messages)
            if app.display_guest_view {
                // TODO: this is not efficient at all
                if m.text.text().starts_with(&app.members_tag)
                    || m.text.text().starts_with(&app.staffs_tag)
                {
                    return None;
                }
                if let Some((_, Some(_), _)) = get_message(&m.text, &app.members_tag) {
                    return None;
                }
            }

            if app.filter != "" {
                if !m
                    .text
                    .text()
                    .to_lowercase()
                    .contains(&app.filter.to_lowercase())
                {
                    return None;
                }
            }

            app.items.items.push(m.clone());

            let new_lines = gen_lines(&m.text, (r.width - 20) as usize, " ".repeat(17));

            let mut rows = vec![];
            let date_style = match (m.deleted, m.hide) {
                (false, true) => Style::default().fg(tuiColor::Gray),
                (false, _) => Style::default().fg(tuiColor::DarkGray),
                (true, _) => Style::default().fg(tuiColor::Red),
            };
            let mut spans_vec = vec![Span::styled(m.date.clone(), date_style)];
            let show_sys_sep = app.show_sys && m.typ == MessageType::SysMsg;
            let sep = if show_sys_sep { " * " } else { " - " };
            spans_vec.push(Span::raw(sep));
            for (idx, line) in new_lines.into_iter().enumerate() {
                // Spams can take your whole screen, so we limit to 5 lines.
                if idx >= 5 {
                    spans_vec.push(Span::styled(
                        "                 […]",
                        Style::default().fg(tuiColor::White),
                    ));
                    rows.push(Spans::from(spans_vec.clone()));
                    break;
                }
                for (color, txt) in line {
                    spans_vec.push(Span::styled(txt, Style::default().fg(color)));
                }
                rows.push(Spans::from(spans_vec.clone()));
                spans_vec.clear();
            }

            let mut list_item = ListItem::new(rows);
            if m.deleted {
                list_item = list_item.style(Style::default().bg(tuiColor::Rgb(30, 0, 0)));
            } else if m.hide {
                list_item = list_item.style(Style::default().bg(tuiColor::Rgb(20, 20, 20)));
            }

            Some(list_item)
        })
        .collect();

    let messages_list = List::new(messages_list_items)
        .block(Block::default().borders(Borders::ALL).title("Messages"))
        .highlight_style(
            Style::default()
                .bg(tuiColor::Rgb(50, 50, 50))
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(messages_list, r, &mut app.items.state)
}

fn render_users(f: &mut Frame<CrosstermBackend<io::Stdout>>, r: Rect, users: &Arc<Mutex<Users>>) {
    // Users lists
    let users = users.lock().unwrap();
    let mut users_list: Vec<ListItem> = vec![];
    let mut users_types: Vec<&Vec<(tuiColor, String)>> = Vec::new();
    users_types.push(&users.admin);
    users_types.push(&users.staff);
    users_types.push(&users.members);
    users_types.push(&users.guests);
    for (i, users_type) in users_types.iter().enumerate() {
        match i {
            0 => users_list.push(ListItem::new(Span::raw("-- Admin --"))),
            1 => users_list.push(ListItem::new(Span::raw("-- Staff --"))),
            2 => users_list.push(ListItem::new(Span::raw("-- Members --"))),
            3 => users_list.push(ListItem::new(Span::raw("-- Guests --"))),
            _ => {}
        }
        for (tui_color, username) in users_type.iter() {
            let span = Span::styled(username, Style::default().fg(*tui_color));
            users_list.push(ListItem::new(span));
        }
    }
    let users = List::new(users_list).block(Block::default().borders(Borders::ALL).title("Users"));
    f.render_widget(users, r);
}

fn random_string(n: usize) -> String {
    let s: Vec<u8> = thread_rng().sample_iter(&Alphanumeric).take(n).collect();
    std::str::from_utf8(&s).unwrap().to_owned()
}

enum InputMode {
    LongMessage,
    Normal,
    Editing,
}

/// App holds the state of the application
struct App {
    /// Current value of the input box
    input: String,
    input_idx: usize,
    /// Current input mode
    input_mode: InputMode,
    is_muted: bool,
    show_sys: bool,
    display_guest_view: bool,
    display_hidden_msgs: bool,
    items: StatefulList<Message>,
    filter: String,
    members_tag: String,
    staffs_tag: String,
    long_message: Option<Message>,
}

impl Default for App {
    fn default() -> App {
        App {
            input: String::new(),
            input_idx: 0,
            input_mode: InputMode::Normal,
            is_muted: false,
            show_sys: false,
            display_guest_view: false,
            display_hidden_msgs: false,
            items: StatefulList::new(),
            filter: "".to_owned(),
            members_tag: "".to_owned(),
            staffs_tag: "".to_owned(),
            long_message: None,
        }
    }
}

impl App {
    fn update_filter(&mut self) {
        if let Some(captures) = FIND_RGX.captures(&self.input) {
            // Find
            self.filter = captures.get(1).map_or("", |m| m.as_str()).to_owned();
        }
    }

    fn clear_filter(&mut self) {
        if FIND_RGX.is_match(&self.input) {
            self.filter = "".to_owned();
            self.input = "".to_owned();
            self.input_idx = 0;
        }
    }
}

pub enum Event<I> {
    Input(I),
    Tick,
    Terminate,
    NeedLogin,
}

/// A small event handler that wrap termion input and tick events. Each event
/// type is handled in its own thread and returned to a common `Receiver`
struct Events {
    messages_updated_rx: crossbeam_channel::Receiver<bool>,
    exit_rx: crossbeam_channel::Receiver<ExitSignal>,
    rx: crossbeam_channel::Receiver<Event<CEvent>>,
}

#[derive(Debug, Clone)]
struct Config {
    pub exit_rx: crossbeam_channel::Receiver<ExitSignal>,
    pub messages_updated_rx: crossbeam_channel::Receiver<bool>,
    pub tick_rate: Duration,
}

impl Events {
    fn with_config(config: Config) -> (Events, thread::JoinHandle<()>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let tick_rate = config.tick_rate;
        let exit_rx = config.exit_rx;
        let messages_updated_rx = config.messages_updated_rx;
        let exit_rx1 = exit_rx.clone();
        let h = thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                // poll for tick rate duration, if no events, sent tick event.
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or_else(|| Duration::from_secs(0));
                if event::poll(timeout).unwrap() {
                    let evt = event::read().unwrap();
                    match evt {
                        CEvent::Resize(_, _) => tx.send(Event::Input(evt)).unwrap(),
                        CEvent::Key(_) => tx.send(Event::Input(evt)).unwrap(),
                        CEvent::Mouse(mouse_event) => {
                            match mouse_event.kind {
                                event::MouseEventKind::ScrollDown
                                | event::MouseEventKind::ScrollUp
                                | event::MouseEventKind::Down(_) => {
                                    tx.send(Event::Input(evt)).unwrap();
                                }
                                _ => {}
                            };
                        }
                    };
                }
                if last_tick.elapsed() >= tick_rate {
                    select! {
                        recv(&exit_rx1) -> _ => break,
                        default => {},
                    }
                    last_tick = Instant::now();
                }
            }
        });
        (
            Events {
                rx,
                exit_rx,
                messages_updated_rx,
            },
            h,
        )
    }

    fn next(&self) -> std::result::Result<Event<CEvent>, crossbeam_channel::RecvError> {
        select! {
            recv(&self.rx) -> evt => evt,
            recv(&self.messages_updated_rx) -> _ => Ok(Event::Tick),
            recv(&self.exit_rx) -> v => match v {
                Ok(ExitSignal::Terminate) => Ok(Event::Terminate),
                Ok(ExitSignal::NeedLogin) => Ok(Event::NeedLogin),
                Err(_) => Ok(Event::Terminate),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_lines_test() {
        let txt = StyledText::Styled(
            tuiColor::White,
            vec![
                StyledText::Styled(
                    tuiColor::Rgb(255, 255, 255),
                    vec![
                        StyledText::Text(" prmdbba pwuv💓".to_owned()),
                        StyledText::Styled(
                            tuiColor::Rgb(255, 255, 255),
                            vec![StyledText::Styled(
                                tuiColor::Rgb(0, 255, 0),
                                vec![StyledText::Text("PMW".to_owned())],
                            )],
                        ),
                        StyledText::Styled(
                            tuiColor::Rgb(255, 255, 255),
                            vec![StyledText::Styled(
                                tuiColor::Rgb(255, 255, 255),
                                vec![StyledText::Text("A".to_owned())],
                            )],
                        ),
                        StyledText::Styled(
                            tuiColor::Rgb(255, 255, 255),
                            vec![StyledText::Styled(
                                tuiColor::Rgb(0, 255, 0),
                                vec![StyledText::Text("XOS".to_owned())],
                            )],
                        ),
                        StyledText::Text(
                            "pqb a mavx pkj fhsoeycg oruzb asd lk ruyaq re lheot mbnrw ".to_owned(),
                        ),
                    ],
                ),
                StyledText::Text(" - ".to_owned()),
                StyledText::Styled(
                    tuiColor::Rgb(255, 255, 255),
                    vec![StyledText::Text("rytxvgs".to_owned())],
                ),
            ],
        );
        let lines = gen_lines(&txt, 71, "".to_owned());
        assert_eq!(lines.len(), 2);
    }
}
