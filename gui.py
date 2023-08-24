import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pymongo
import bcrypt
from decouple import config
from urllib.parse import urlparse

MONGODB_URI = config('MONGODB_URI')
client = pymongo.MongoClient(MONGODB_URI)
db = client.passwords_db
app_users = db.app_users
passwords = db.passwords

current_user_id = None


def register():
    username, password = entry_username.get(), entry_password.get()
    if not username or not password:
        return messagebox.showerror("Error", "Please enter both username and password!")
    if app_users.find_one({"username": username}):
        return messagebox.showerror("Error", "Username already exists!")
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    app_users.insert_one({"username": username, "password": hashed})
    messagebox.showinfo("Success", "Registration successful!")


def login(event=None):
    global current_user_id
    username, password = entry_username.get(), entry_password.get()
    user = app_users.find_one({"username": username})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        return messagebox.showerror("Error", "Invalid credentials!")
    current_user_id = user['_id']
    switch_frames(login_frame, password_manager_frame)
    display_passwords()


def switch_frames(frame_to_hide, frame_to_show):
    frame_to_hide.pack_forget()
    frame_to_show.pack(fill=tk.BOTH, expand=True)


def add_password():
    show_sidebar()


def display_passwords():
    password_table.delete(*password_table.get_children())
    search_query = search_bar.get()
    for pwd in passwords.find({"user_id": current_user_id, "platform": {'$regex': search_query, '$options': 'i'}}):
        password_table.insert("", "end", values=(
            pwd["platform"], pwd["username"], "******", ",".join(pwd["tags"])))


def reveal_password():
    item = password_table.selection()[0]
    password = password_table.item(item, "tags")[1]
    password_table.set(item, "Password", password)


def copy_to_clipboard():
    item = password_table.selection()[0]
    password = password_table.item(item, "tags")[1]
    app.clipboard_clear()
    app.clipboard_append(password)


def on_right_click(event):
    password_table.selection_set(password_table.identify_row(event.y))
    right_click_menu.post(event.x_root, event.y_root)


def logout():
    global current_user_id
    current_user_id = None
    switch_frames(password_manager_frame, login_frame)
    entry_username.delete(0, tk.END)
    entry_password.delete(0, tk.END)


def hide_sidebar():
    sidebar_frame.pack_forget()
    add_button.pack(side="left")


def show_sidebar():
    sidebar_frame.pack(side="right", fill="y")
    add_button.pack_forget()


def save_password():
    platform_link, platform_username, platform_password, tags = entry_platform_link.get(
    ), entry_platform_username.get(), entry_platform_password.get(), entry_tags.get().split(",")[:3]
    platform_name = urlparse(platform_link).netloc.split('.')[0]
    passwords.insert_one({
        "platform": platform_name,
        "link": platform_link,
        "username": platform_username,
        "password": platform_password,
        "tags": tags,
        "user_id": current_user_id,
        "organization": entry_organization.get(),
        "database_name": entry_db_name.get(),
        "database_password": entry_db_password.get(),
        "region": entry_region.get(),
        "pricing": entry_pricing.get(),
        "platform_type": entry_platform_type.get(),
        "token_public": entry_token_public.get(),
        "token_private": entry_token_private.get(),
        "email": entry_email.get()
    })
    display_passwords()
    hide_sidebar()


def upload_image():
    file_path = filedialog.askopenfilename(
        filetypes=[('Image Files', '*.png;*.jpg;*.jpeg')])
    if file_path:
        messagebox.showinfo(
            "Image", f"Image saved at {file_path}. Remember, if you delete the app, the image will be lost.")


app = tk.Tk()
app.title("Password Manager")
app.geometry("1400x700")
app.minsize(1400, 700)

# Login Frame
login_frame = ttk.Frame(app)
login_frame.pack(fill=tk.BOTH, expand=True)

entry_username, entry_password = ttk.Entry(
    login_frame), ttk.Entry(login_frame, show="*")
entry_password.bind('<Return>', login)

for widget, row, text in zip([entry_username, entry_password], range(2), ["Username", "Password"]):
    ttk.Label(login_frame, text=text).grid(row=row, column=0, pady=5)
    widget.grid(row=row, column=1, pady=5, padx=5)

ttk.Button(login_frame, text="Login", command=login).grid(
    row=2, column=0, pady=10, padx=5, sticky='e')
ttk.Button(login_frame, text="Sign Up", command=register).grid(
    row=2, column=1, pady=10, padx=5, sticky='w')

# Password Manager Frame
password_manager_frame = ttk.Frame(app)
search_bar = ttk.Entry(password_manager_frame)
search_bar.bind('<KeyRelease>', lambda e: display_passwords())

password_table = ttk.Treeview(password_manager_frame, columns=(
    "Platform", "Username", "Password", "Tags"), show="headings")
for col, text in zip(password_table["columns"], ["Platform", "Username", "Password", "Tags"]):
    password_table.heading(col, text=text)

password_table.bind('<Button-3>', on_right_click)
password_table.bind('<Double-1>', reveal_password)

right_click_menu = tk.Menu(app, tearoff=0)
right_click_menu.add_command(label="Reveal", command=reveal_password)
right_click_menu.add_command(
    label="Copy to Clipboard", command=copy_to_clipboard)

# Sidebar for adding passwords
sidebar_frame = ttk.Frame(password_manager_frame)
entries = {
    "Platform Link": tk.StringVar(),
    "Username": tk.StringVar(),
    "Password": tk.StringVar(),
    "Tags (comma-separated)": tk.StringVar(),
    "Organization": tk.StringVar(),
    "Database Name": tk.StringVar(),
    "Database Password": tk.StringVar(),
    "Region": tk.StringVar(),
    "Pricing": tk.StringVar(),
    "Platform Type": tk.StringVar(),
    "Token Public": tk.StringVar(),
    "Token Private": tk.StringVar(),
    "Email": tk.StringVar()
}

for label_text, variable in entries.items():
    ttk.Label(sidebar_frame, text=label_text).pack(pady=5, padx=10)
    if "Password" in label_text:
        ttk.Entry(sidebar_frame, textvariable=variable,
                  show="*").pack(pady=5, padx=10, fill=tk.X)
    else:
        ttk.Entry(sidebar_frame, textvariable=variable).pack(
            pady=5, padx=10, fill=tk.X)

upload_button = ttk.Button(
    sidebar_frame, text="Upload Image", command=upload_image)

ttk.Button(sidebar_frame, text="Hide", command=hide_sidebar).pack(
    side="left", pady=10, padx=10)
ttk.Button(sidebar_frame, text="Save", command=save_password).pack(
    side="right", pady=10, padx=10)

for widget in [search_bar, password_table, upload_button]:
    widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

button_frame = ttk.Frame(password_manager_frame)
add_button = ttk.Button(button_frame, text="+", command=show_sidebar)
logout_button = ttk.Button(button_frame, text="Logout", command=logout)

for widget in [add_button, logout_button]:
    widget.pack(side="left" if widget ==
                add_button else "right", pady=10, padx=10)

button_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

app.mainloop()
