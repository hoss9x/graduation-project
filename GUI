import os
import json
import datetime
import customtkinter as ctk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import threading
import subprocess

REPORTS_DIR = "Reports"
RULE_BASED_SCRIPT = "spam_rules.py"
AI_BASED_SCRIPT = "spam_ai.py"

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SplashScreen(ctk.CTk):
    def __init__(self, parent_callback):
        super().__init__()
        self.parent_callback = parent_callback
        self.attributes("-fullscreen", True)
        self.configure(bg="#1e1e1e")
        self.attributes("-alpha", 1.0)

        center_frame = ctk.CTkFrame(self, fg_color="transparent")
        center_frame.pack(expand=True)

        self.label = ctk.CTkLabel(center_frame, text="Email Scanner", font=("Arial", 36, "bold"), text_color="white")
        self.label.pack(pady=30)

        self.progress = ctk.CTkProgressBar(center_frame, mode="determinate", width=400)
        self.progress.pack(pady=10)
        self.progress.set(0)

        self.percent = 0
        self.after(50, self.update_progress)

        self.bind("<Escape>", lambda e: self.destroy())

    def update_progress(self):
        if self.percent < 1.0:
            self.percent += 0.02
            self.progress.set(self.percent)
            self.after(50, self.update_progress)
        else:
            self.fade_out()

    def fade_out(self):
        alpha = self.attributes("-alpha")
        if alpha > 0:
            self.attributes("-alpha", alpha - 0.05)
            self.after(50, self.fade_out)
        else:
            self.destroy()
            self.parent_callback()

class EmailDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Email Scanner Dashboard")
        self.attributes('-fullscreen', True)
        self.bind("<Escape>", lambda e: self.attributes('-fullscreen', False))

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._closing = False
        self.polling_active = False
        self.scan_process = None

        self.data = []
        self.filtered_data = []

        self.create_widgets()
        self.load_data()
        self.apply_filter("week")

    def create_widgets(self):
        self.option_frame = ctk.CTkFrame(self)
        self.option_frame.pack(pady=10, fill="x")

        self.stop_btn = ctk.CTkButton(self.option_frame, text="\U0001F6D1 Stop Scan", command=self.stop_scanner, state="disabled")
        self.stop_btn.pack(side="left", padx=10)

        self.status_label = ctk.CTkLabel(self.option_frame, text="Status: Idle", text_color="gray")
        self.status_label.pack(side="left", padx=10)

        self.scan_btn1 = ctk.CTkButton(self.option_frame, text="\U0001F4E5 Run Rule-Based Scan", command=lambda: self.run_scanner(RULE_BASED_SCRIPT))
        self.scan_btn2 = ctk.CTkButton(self.option_frame, text="\U0001F9E0 Run AI-Based Scan", command=lambda: self.run_scanner(AI_BASED_SCRIPT))
        self.scan_btn1.pack(side="left", padx=10)
        self.scan_btn2.pack(side="left", padx=10)

        self.progress = ctk.CTkProgressBar(self.option_frame, mode="indeterminate")
        self.progress.pack(side="left", padx=10)
        self.progress.stop()
        self.status_label.configure(text="Status: Idle", text_color="gray")
        self.progress.configure(width=200)

        self.filter_label = ctk.CTkLabel(self.option_frame, text="Show statistics for:")
        self.filter_label.pack(side="left", padx=10)

        self.filter_var = ctk.StringVar(value="week")
        self.filter_week = ctk.CTkRadioButton(self.option_frame, text="Last Week", variable=self.filter_var, value="week", command=self.update_charts)
        self.filter_month = ctk.CTkRadioButton(self.option_frame, text="Last Month", variable=self.filter_var, value="month", command=self.update_charts)
        self.filter_week.pack(side="left")
        self.filter_month.pack(side="left")

        self.banner_label = ctk.CTkLabel(self, text="", font=("Arial", 12))
        self.banner_label.pack(side="bottom", pady=20)


        self.chart_frame = ctk.CTkScrollableFrame(self)
        self.chart_frame.pack(expand=True, fill="both", padx=10, pady=(5, 20))
        self.chart_frame.grid_columnconfigure(0, weight=1)
        self.chart_frame.grid_columnconfigure(1, weight=1)

        self.table = ttk.Treeview(self, columns=("from", "subject", "label", "score", "date", "source"), show="headings")
        for col in self.table["columns"]:
            self.table.heading(col, text=col.capitalize())
        self.table.pack(fill="both", expand=True, padx=10, pady=5)

    def run_scanner(self, script_name):
        if self.scan_process and self.scan_process.poll() is None:
            return

        self.stop_btn.configure(state="normal")
        self.progress.start()
        self.status_label.configure(text="Status: Scanning...", text_color="orange")
        self.polling_active = True
        self.start_polling_reports()

        def _run():
            self.scan_process = subprocess.Popen(["python", script_name])
            self.scan_process.wait()
            self.after(100, self.reload_interface_safely)

        threading.Thread(target=_run, daemon=True).start()

    def stop_scanner(self):
        self.polling_active = False
        self.progress.stop()
        self.stop_btn.configure(state="disabled")
        self.status_label.configure(text="Status: Idle", text_color="gray")

        if self.scan_process and self.scan_process.poll() is None:
            self.scan_process.terminate()
            self.scan_process = None

    def reload_interface_safely(self):
        if getattr(self, '_closing', False): return
        self.load_data()
        self.apply_filter(self.filter_var.get())
        self.stop_btn.configure(state="disabled")
        self.progress.stop()
        self.status_label.configure(text="Status: Idle", text_color="gray")

    def load_data(self):
        self.data.clear()
        sources = {
            "Reports/Rules": "rule_based",
            "Reports/AI": "ai_based"
        }

        for base_path, source_label in sources.items():
            if not os.path.isdir(base_path):
                continue

            for day_folder in os.listdir(base_path):
                folder_path = os.path.join(base_path, day_folder)
                if os.path.isdir(folder_path):
                    for file in os.listdir(folder_path):
                        if file.endswith(".json"):
                            with open(os.path.join(folder_path, file), encoding="utf-8") as f:
                                report = json.load(f)
                                self.data.append({
                                    "date": day_folder,
                                    "from": report.get("from", "-"),
                                    "subject": report.get("subject", file.replace(".json", "")),
                                    "label": report.get("label", "Unknown"),
                                    "score": report.get("spam_score", 0),
                                    "source": source_label
                                })

    def apply_filter(self, mode):
        today = datetime.date.today()
        days = 7 if mode == "week" else 30
        start_date = today - datetime.timedelta(days=days)
        self.filtered_data = [d for d in self.data if datetime.datetime.strptime(d['date'], "%Y-%m-%d").date() >= start_date]
        self.update_table()
        self.plot_charts()

    def update_charts(self):
        if getattr(self, '_closing', False): return
        self.apply_filter(self.filter_var.get())

    def update_table(self):
        if getattr(self, '_closing', False): return
        for row in self.table.get_children():
            self.table.delete(row)
        for item in sorted(self.filtered_data, key=lambda x: x['date'], reverse=True):
            self.table.insert("", "end", values=(item['from'], item['subject'], item['label'], item['score'], item['date'], item['source']))

    def plot_charts(self):
        if getattr(self, '_closing', False): return
        for widget in self.chart_frame.winfo_children():
            widget.destroy()
        plt.close('all')

        df = pd.DataFrame(self.filtered_data)
        if df.empty:
            self.banner_label.configure(text="")
            return

        label_colors = {
                "Safe": "#00FF00", "safe": "#00FF00",
                "Suspicious": "#FFEE00", "suspicious": "#FFEE00",
                "Likely Spam": "#FFA600", "likely spam": "#FFA600",
                "High Risk (Spam)": "#FF0000", "high risk (spam)": "#FF0000",
                "Unknown": "#5F5959", "unknown": "#5F5959"
        }


        total_peak_day = "-"
        total_peak_value = 0
        spam_peak_day = "-"
        spam_peak_value = 0

        row = 0
        col = 0

        for source in ['rule_based', 'ai_based']:
            src_df = df[df['source'] == source].copy()
            if src_df.empty:
                continue

            # التحويل الآمن
            src_df['date'] = pd.to_datetime(src_df['date'], errors='coerce')
            src_df = src_df.dropna(subset=['date'])

            # إذا أصبح فارغ بعد التنظيف، تجاهله
            if src_df.empty:
                continue



            # Pie Chart
            label_counts = src_df['label'].value_counts()
            pie_colors = [label_colors.get(label, "#9E9E9E") for label in label_counts.index]

            fig1, ax1 = plt.subplots(figsize=(3.5, 2.5))
            ax1.pie(label_counts, labels=label_counts.index, autopct='%1.1f%%', colors=pie_colors)
            ax1.set_title(f"Email Types Ratio ({'Rules' if source == 'rule_based' else 'AI'})")
            canvas1 = FigureCanvasTkAgg(fig1, master=self.chart_frame)
            canvas1.draw()
            canvas1.get_tk_widget().grid(row=row, column=col, padx=7, pady=7, sticky="nsew")
            canvas1.get_tk_widget().configure(height=250)  # ← لتقليص ارتفاع كل رسم

            # Bar Chart
            daily_counts = src_df.groupby([src_df['date'].dt.date, 'label']).size().unstack(fill_value=0)
            bar_colors = [label_colors.get(label, "#9E9E9E") for label in daily_counts.columns]

            fig2, ax2 = plt.subplots(figsize=(4, 2.5))
            daily_counts.plot(kind='bar', stacked=True, ax=ax2, color=bar_colors)
            ax2.set_title(f"Email Count by Day ({'Rules' if source == 'rule_based' else 'AI'})")
            canvas2 = FigureCanvasTkAgg(fig2, master=self.chart_frame)
            canvas2.draw()
            canvas2.get_tk_widget().grid(row=row+1, column=col, padx=7, pady=7, sticky="nsew")
            canvas2.get_tk_widget().configure(height=250)  # ← لتقليص ارتفاع كل رسم
            
            # Peak info
            total_per_day = daily_counts.sum(axis=1)
            peak_day_total = total_per_day.idxmax()
            peak_total_value = total_per_day.max()

            if peak_total_value > total_peak_value:
                total_peak_day = peak_day_total
                total_peak_value = peak_total_value

            if "High Risk (Spam)" in daily_counts.columns:
                spam_per_day = daily_counts["High Risk (Spam)"]
                peak_day_spam_candidate = spam_per_day.idxmax()
                peak_spam_value_candidate = spam_per_day.max()
                if peak_spam_value_candidate > spam_peak_value:
                    spam_peak_day = peak_day_spam_candidate
                    spam_peak_value = peak_spam_value_candidate

            col += 1  # يمين للرسمة التالية

        self.banner_label.configure(
            text=f"Peak Day: {total_peak_day} ({total_peak_value} emails) | Spam Peak: {spam_peak_day} ({spam_peak_value} spam)",
            text_color="white"
        )



    def start_polling_reports(self):
        def poll():
            if getattr(self, '_closing', False) or not getattr(self, 'polling_active', False):
                return
            self.load_data()
            self.apply_filter(self.filter_var.get())
            self.after(5000, poll)
        self.after(5000, poll)

    def on_close(self):
        self._closing = True
        try:
            self.progress.stop()
            if self.scan_process and self.scan_process.poll() is None:
                self.scan_process.terminate()
            for widget in self.chart_frame.winfo_children():
                widget.destroy()
            plt.close('all')
        except:
            pass
        self.destroy()

if __name__ == "__main__":
    SplashScreen(lambda: EmailDashboard().mainloop()).mainloop()
