#include "gui.h"
#include "config.h"
#include "volume.h"
#include "vfs.h"
#include "utils.h"
#include "fuse_mount.h"
#include <gtk/gtk.h>
#include <glib.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Forward declarations */
static void on_create_volume_clicked(GtkWidget *widget, gpointer data);
static void on_open_volume_clicked(GtkWidget *widget, gpointer data);
static void on_mount_volume_clicked(GtkWidget *widget, gpointer data);
static void on_unmount_volume_clicked(GtkWidget *widget, gpointer data);
static void on_close_volume_clicked(GtkWidget *widget, gpointer data);
static void on_toggle_password(GtkWidget *widget, gpointer data);
static void on_about_clicked(GtkWidget *widget, gpointer data);
static void on_quit_clicked(GtkWidget *widget, gpointer data);
static GdkPixbuf* load_app_logo(int size);
static int check_license_verification(void) __attribute__((unused));
static void on_browse_clicked(GtkWidget *widget, gpointer data);
static void on_volume_path_changed(GtkWidget *widget, gpointer data);
static void update_telemetry(AppState *app);


/* Progress callback data */
typedef struct {
    GtkWidget *progress_bar;
    GtkWidget *status_label;
    GtkApplication *app;
} ProgressData;

/* Progress callback for volume operations */
static void progress_callback(const char *label, size_t cur, size_t total, void *user_data) {
    ProgressData *data = (ProgressData *)user_data;
    if (!data) return;
    
    double fraction = (total > 0) ? (double)cur / total : 0.0;
    char status_text[256];
    snprintf(status_text, sizeof(status_text), "%s: %.1f%%", label, fraction * 100.0);
    
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(data->progress_bar), fraction);
    gtk_label_set_text(GTK_LABEL(data->status_label), status_text);
    
    while (gtk_events_pending()) gtk_main_iteration();
}

/* Show error dialog */
void show_error_dialog(GtkWidget *parent, const char *message) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(parent),
        GTK_DIALOG_MODAL,
        GTK_MESSAGE_ERROR,
        GTK_BUTTONS_OK,
        "%s", message
    );
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Show info dialog */
void show_info_dialog(GtkWidget *parent, const char *message) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(parent),
        GTK_DIALOG_MODAL,
        GTK_MESSAGE_INFO,
        GTK_BUTTONS_OK,
        "%s", message
    );
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Show warning dialog */
void show_warning_dialog(GtkWidget *parent, const char *message) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(parent),
        GTK_DIALOG_MODAL,
        GTK_MESSAGE_WARNING,
        GTK_BUTTONS_OK,
        "%s", message
    );
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* File chooser dialog */
static char* choose_file(GtkWidget *parent, const char *title, GtkFileChooserAction action) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        title,
        GTK_WINDOW(parent),
        action,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Select", GTK_RESPONSE_ACCEPT,
        NULL
    );
    
    char *filename = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    }
    gtk_widget_destroy(dialog);
    return filename;
}

static void update_telemetry(AppState *app) {
    if (!app) return;
    
    /* 1. Active Volume File */
    if (app->current_volume && app->current_volume->is_open) {
        char *path = app->current_volume->path;
        if (path && *path) {
            char *base = g_path_get_basename(path);
            char *markup = g_strdup_printf("<span font_desc='monospace 10' color='#ffffff'>%s</span>", base);
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), markup);
            g_free(base);
            g_free(markup);
        } else {
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), "<span color='#888888'>None</span>");
        }
    } else {
        const char *entry_path = gtk_entry_get_text(GTK_ENTRY(app->volume_path_entry));
        if (entry_path && *entry_path) {
            char *base = g_path_get_basename(entry_path);
            char *markup = g_strdup_printf("<span font_desc='monospace 10' color='#888888'>%s (unopened)</span>", base);
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), markup);
            g_free(base);
            g_free(markup);
        } else {
            gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_path), "<span color='#888888'>None</span>");
        }
    }
    
    /* 2. Decryption Lock State */
    if (app->current_volume && app->current_volume->is_open) {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_lock), "<span color='#00ffcc'>●</span> UNLOCKED");
    } else {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_lock), "<span color='#ff3333'>●</span> LOCKED");
    }
    
    /* 3. Mount Status */
    if (app->current_volume && app->current_volume->is_open && app->current_volume->vfs.is_mounted) {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_mount), "<span color='#00ffcc'>●</span> ACTIVE");
    } else {
        gtk_label_set_markup(GTK_LABEL(app->lbl_telemetry_mount), "<span color='#ff3333'>●</span> INACTIVE");
    }
}

static void on_browse_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    char *path = choose_file(app->window, "Select Encrypted Volume File", GTK_FILE_CHOOSER_ACTION_OPEN);
    if (path) {
        gtk_entry_set_text(GTK_ENTRY(app->volume_path_entry), path);
        g_free(path);
    }
}

static void on_volume_path_changed(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    update_telemetry(app);
}

/* Create volume callback */
static void on_create_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    const char *path = gtk_entry_get_text(GTK_ENTRY(app->volume_path_entry));
    const char *size_str = gtk_entry_get_text(GTK_ENTRY(app->volume_size_entry));
    const char *password = gtk_entry_get_text(GTK_ENTRY(app->password_entry));

    if (!path || !*path) {
        show_error_dialog(app->window, "Please enter a volume file path.");
        return;
    }
    if (!size_str || !*size_str) {
        show_error_dialog(app->window, "Please enter volume size in MB.");
        return;
    }
    if (!password || !*password) {
        show_error_dialog(app->window, "Please enter a password.");
        return;
    }

    /* Use strtol so we can detect non-numeric input and overflow */
    char *end = NULL;
    long size_mb_l = strtol(size_str, &end, 10);
    if (!end || *end != '\0' || size_mb_l <= 0) {
        show_error_dialog(app->window, "Please enter a valid numeric volume size.");
        return;
    }
    if (size_mb_l < 10) {
        show_error_dialog(app->window, "Volume size must be at least 10 MB.");
        return;
    }
    if (size_mb_l > 1024 * 1024) {  /* cap at 1 TiB */
        show_error_dialog(app->window, "Volume size must not exceed 1048576 MB (1 TiB).");
        return;
    }
    size_t size_mb = (size_t)size_mb_l;

    gtk_label_set_text(GTK_LABEL(app->status_label), "Creating volume...");

    ProgressData prog_data = {
        .progress_bar = app->progress_bar,
        .status_label = app->status_label
    };

    int result = volume_create(path, size_mb, password, progress_callback, &prog_data);

    /* Wipe password from GTK widget memory immediately after use */
    gtk_entry_set_text(GTK_ENTRY(app->password_entry), "");

    if (result == 0) {
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 1.0);
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume created successfully!");
        show_info_dialog(app->window, "Volume created successfully!");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume creation failed!");
        show_error_dialog(app->window, "Failed to create volume. Check permissions and try again.");
    }
    update_telemetry(app);
}

/* Open volume callback */
static void on_open_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    char *path = choose_file(app->window, "Select Volume File", GTK_FILE_CHOOSER_ACTION_OPEN);
    if (!path) {
        return;
    }

    const char *password = gtk_entry_get_text(GTK_ENTRY(app->password_entry));
    if (!password || !*password) {
        show_error_dialog(app->window, "Please enter a password.");
        g_free(path);
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Opening volume...");

    if (app->current_volume) {
        if (app->current_volume->is_open) {
            if (app->current_volume->vfs.is_mounted) {
                stop_fuse_mount(app->current_volume);
                volume_unmount(app->current_volume);
            }
            volume_close(app->current_volume, NULL, NULL);
            free(app->current_volume);
        }
    }

    app->current_volume = malloc(sizeof(volume_context_t));
    memset(app->current_volume, 0, sizeof(volume_context_t));

    if (lock_sensitive(app->current_volume, sizeof(volume_context_t)) != 0) {
        show_warning_dialog(app->window, 
            "Warning: Memory locking failed.\n\n"
            "The master key may be swapped to disk. Run as root or increase memlock limits to ensure maximum security.");
    }

    /* Set up progress callback */
    ProgressData progress_data = {
        .progress_bar = app->progress_bar,
        .status_label = app->status_label,
        .app = GTK_APPLICATION(gtk_window_get_application(GTK_WINDOW(app->window)))
    };

    /* Ensure UI updates are processed before opening volume */
    gtk_label_set_text(GTK_LABEL(app->status_label), "Preparing to open volume...");
    /* Process all pending events to ensure dialog cleanup */
    while (gtk_events_pending()) gtk_main_iteration();
    /* Force a UI update cycle */
    GdkDisplay *display = gdk_display_get_default();
    if (display) {
        gdk_display_flush(display);
    }

    int result = volume_open(path, password, app->current_volume, progress_callback, &progress_data);

    /* Wipe password from GTK widget memory immediately after use */
    gtk_entry_set_text(GTK_ENTRY(app->password_entry), "");

    if (result == 0) {
        gtk_entry_set_text(GTK_ENTRY(app->volume_path_entry), path);
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume opened successfully!");
        show_info_dialog(app->window, "Volume opened! Click 'Mount' to access files.");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to open volume!");
        /* Distinguish Argon2 memory failure from wrong password.
         * derive_master_key uses 1 GiB of RAM; on low-memory systems
         * crypto_pwhash returns -1 before even comparing the password. */
        show_error_dialog(app->window,
            "Failed to open volume.\n\n"
            "This can mean:\n"
            "  \xe2\x80\xa2 Wrong password\n"
            "  \xe2\x80\xa2 Corrupted volume file\n"
            "  \xe2\x80\xa2 Insufficient RAM for Argon2 (needs ~1 GB free)");
        free(app->current_volume);
        app->current_volume = NULL;
    }

    g_free(path);
    update_telemetry(app);
}

/* Mount volume callback */static void on_check_space_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    if (!app->current_volume || !app->current_volume->vfs.is_mounted) return;
    
    uint64_t total = (uint64_t)app->current_volume->vfs.header.total_sectors * VFS_SECTOR_SIZE;
    uint64_t used = (uint64_t)app->current_volume->vfs.header.used_sectors * VFS_SECTOR_SIZE;
    uint64_t free_bytes = total > used ? total - used : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Total space: %.2f MB\nUsed space: %.2f MB\nFree space: %.2f MB",
             (double)total / (1024*1024), (double)used / (1024*1024), (double)free_bytes / (1024*1024));
    show_info_dialog(app->window, msg);
}

static void on_mount_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    if (!app->current_volume || !app->current_volume->is_open) {
        show_error_dialog(app->window, "No volume is currently open.");
        return;
    }

    if (app->current_volume->vfs.is_mounted) {
        stop_fuse_mount(app->current_volume);
        volume_unmount(app->current_volume);
    }
    if (0) {
        show_error_dialog(app->window, "Volume is already mounted.");
        return;
    }

    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Select Mount Directory",
        GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Mount", GTK_RESPONSE_ACCEPT,
        NULL
    );
    
    char *mount_dir = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        mount_dir = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    }
    gtk_widget_destroy(dialog);
    
    if (!mount_dir) {
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Mounting volume...");

    int result = volume_mount(app->current_volume);
    if (result == 0) {
        if (start_fuse_mount(app->current_volume, mount_dir) != 0) {
            volume_unmount(app->current_volume);
            show_error_dialog(app->window, "Failed to start FUSE daemon.");
        } else {
            gtk_label_set_text(GTK_LABEL(app->status_label), "Volume mounted via FUSE!");
            if (app->btn_check_space) gtk_widget_set_sensitive(app->btn_check_space, TRUE);
            show_info_dialog(app->window, "Volume mounted successfully via FUSE!");
        }
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to mount volume!");
        show_error_dialog(app->window, "Failed to mount volume. The filesystem may be corrupted.");
    }
    g_free(mount_dir);
    update_telemetry(app);
}

/* Unmount volume callback */
static void on_unmount_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    if (!app->current_volume || !app->current_volume->vfs.is_mounted) {
        show_error_dialog(app->window, "No volume is currently mounted.");
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Unmounting volume...");

    stop_fuse_mount(app->current_volume);
    int result = volume_unmount(app->current_volume);
    if (app->btn_check_space) gtk_widget_set_sensitive(app->btn_check_space, FALSE);
    
    if (result == 0) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume unmounted!");
        show_info_dialog(app->window, "Volume unmounted successfully!");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to unmount volume!");
        show_error_dialog(app->window, "Failed to unmount volume.");
    }
    update_telemetry(app);
}

/* Close volume callback */
static void on_close_volume_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;

    if (!app->current_volume || !app->current_volume->is_open) {
        show_error_dialog(app->window, "No volume is currently open.");
        return;
    }

    if (app->current_volume->vfs.is_mounted) {
        stop_fuse_mount(app->current_volume);
        volume_unmount(app->current_volume);
        if (app->btn_check_space) gtk_widget_set_sensitive(app->btn_check_space, FALSE);
    }
    if (0) {
        show_error_dialog(app->window, "Please unmount the volume before closing.");
        return;
    }

    gtk_label_set_text(GTK_LABEL(app->status_label), "Closing volume...");

    /* Set up progress callback */
    ProgressData progress_data = {
        .progress_bar = app->progress_bar,
        .status_label = app->status_label,
        .app = GTK_APPLICATION(gtk_window_get_application(GTK_WINDOW(app->window)))
    };

    int result = volume_close(app->current_volume, progress_callback, &progress_data);

    if (result == 0) {
        free(app->current_volume);
        app->current_volume = NULL;
        gtk_label_set_text(GTK_LABEL(app->status_label), "Volume closed!");

        show_info_dialog(app->window, "Volume closed successfully!");
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Failed to close volume!");
        show_error_dialog(app->window, "Failed to close volume.");
    }
    update_telemetry(app);
}

/* Toggle password visibility */
static void on_toggle_password(GtkWidget *widget, gpointer data) {
    AppState *app = (AppState *)data;
    app->show_password = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
    gtk_entry_set_visibility(GTK_ENTRY(app->password_entry), app->show_password);
}

/* Helper to add a feature row to the about dialog */
static void add_feature_row(GtkWidget *box, const char *title, const char *desc, const char *icon_symbol) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    gtk_container_set_border_width(GTK_CONTAINER(row), 10);
    
    GtkWidget *icon_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(icon_label), g_strdup_printf("<span size='xx-large'>%s</span>", icon_symbol));
    gtk_widget_set_valign(icon_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(row), icon_label, FALSE, FALSE, 0);
    
    GtkWidget *text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    
    GtkWidget *title_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title_label), g_strdup_printf("<span weight='bold' size='large' color='#00ffcc'>%s</span>", title));
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0);
    gtk_box_pack_start(GTK_BOX(text_vbox), title_label, FALSE, FALSE, 0);
    
    GtkWidget *desc_label = gtk_label_new(desc);
    gtk_label_set_line_wrap(GTK_LABEL(desc_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(desc_label), 0.0);
    gtk_label_set_max_width_chars(GTK_LABEL(desc_label), 60);
    gtk_box_pack_start(GTK_BOX(text_vbox), desc_label, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(row), text_vbox, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 5);
    
    /* Add a subtle separator line */
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_opacity(sep, 0.2);
    gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 0);
}

/* Revamped About dialog */
static void on_about_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    
    GtkWidget *dialog = gtk_dialog_new_with_buttons("About Krakken-Disk",
                                                    GTK_WINDOW(app->window),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "_Close", GTK_RESPONSE_CLOSE,
                                                    NULL);
    
    gtk_window_set_default_size(GTK_WINDOW(dialog), 600, 700);
    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 20);
    gtk_container_add(GTK_CONTAINER(content_area), main_vbox);
    
    /* Header Section */
    GdkPixbuf *logo = load_app_logo(96);
    if (logo) {
        GtkWidget *logo_img = gtk_image_new_from_pixbuf(logo);
        gtk_box_pack_start(GTK_BOX(main_vbox), logo_img, FALSE, FALSE, 0);
        g_object_unref(logo);
    }
    
    GtkWidget *name_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(name_label), "<span size='xx-large' weight='bold' color='white'>Krakken-Disk Manager</span>");
    gtk_box_pack_start(GTK_BOX(main_vbox), name_label, FALSE, FALSE, 0);
    
    GtkWidget *ver_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(ver_label), g_strdup_printf("<span color='#aaaaaa'>Version %s \xe2\x80\xa2 The Apex of Privacy</span>", APP_VERSION));
    gtk_box_pack_start(GTK_BOX(main_vbox), ver_label, FALSE, FALSE, 5);
    
    GtkWidget *sep_top = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_vbox), sep_top, FALSE, FALSE, 10);
    
    /* Scrollable Features Section */
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scrolled, -1, 300);
    gtk_box_pack_start(GTK_BOX(main_vbox), scrolled, TRUE, TRUE, 0);
    
    GtkWidget *feature_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(scrolled), feature_box);
    
    /* Best Features */
    add_feature_row(feature_box, "Uniform 256-bit Post-Quantum Shield", 
        "Engineered for the future. While standard tools offer only 128-bit quantum security, "
        "Krakken-Disk provides a uniform 256-bit security margin across all layers.", "\xf0\x9f\x9b\xa1\xef\xb8\x8f"); /* Shield */

    add_feature_row(feature_box, "Absolute Plausible Deniability", 
        "Volumes are IND-RND compliant. To forensic analysis, your data is mathematically "
        "indistinguishable from random noise. No signatures, no headers, no leaks.", "\xf0\x9f\x8c\x91"); /* New Moon */
    add_feature_row(feature_box, "Hybrid Defense Architecture", 
        "A multi-layered cryptographic shield combining Kyber-1024 and X448. "
        "Protected against both today's supercomputers and tomorrow's quantum threats.", "\xf0\x9f\xa7\xac"); /* DNA */

    add_feature_row(feature_box, "Abyssal Performance Core", 
        "Hand-tuned for AVX2 SIMD. The 2048-bit wide-state permutation delivers "
        "enterprise-grade speeds by processing massive data blocks in parallel.", "\xe2\x9a\xa1"); /* High Voltage */

    add_feature_row(feature_box, "ASIC-Resistant Argon2id", 
        "Armed with 1 GB RAM-locked password hashing. Makes GPU/ASIC-based "
        "brute-force attacks astronomically expensive and inefficient.", "\xf0\x9f\x94\x92"); /* Locked */

    /* Footer / Author */
    GtkWidget *footer_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(footer_label), 
        "<span size='small' color='#666666'>Created by Jean-Francois Lachance-Caumartin (Effjy)\n"
        "Contact: effjy@tutamail.com</span>");
    gtk_label_set_justify(GTK_LABEL(footer_label), GTK_JUSTIFY_CENTER);
    gtk_box_pack_start(GTK_BOX(main_vbox), footer_label, FALSE, FALSE, 10);
    
    /* Using global CSS defined in on_activate */
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Quit callback */
static void on_quit_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    AppState *app = (AppState *)data;
    
    if (app->current_volume) {
        if (app->current_volume->is_open) {
            if (app->current_volume->vfs.is_mounted) {
                stop_fuse_mount(app->current_volume);
                volume_unmount(app->current_volume);
            }
            volume_close(app->current_volume, NULL, NULL);
            free(app->current_volume);
            app->current_volume = NULL;
        }
    }
    
    gtk_window_close(GTK_WINDOW(app->window));
}

/* Helper to load the app logo with fallbacks */
static GdkPixbuf* load_app_logo(int size) {
    GdkPixbuf *logo = NULL;
    GError *error = NULL;
    
    char *cwd = g_get_current_dir();
    char *path_logo1 = g_build_filename(cwd, "krakken_logo.png", NULL);
    char *path_logo2 = g_build_filename(cwd, "krakken-disk-v4.5.0-gtk4", "krakken_logo.png", NULL);
    char *path1 = g_build_filename(cwd, "krakken-disk.svg", NULL);
    char *path2 = g_build_filename(cwd, "krakken-disk-v4.5.0-gtk4", "krakken-disk.svg", NULL);
    
    const char *paths[] = {
        path_logo1,
        path_logo2,
        "krakken_logo.png",
        "krakken-disk-v4.5.0-gtk4/krakken_logo.png",
        "/usr/share/krakken-disk/krakken_logo.png",
        "/usr/local/share/krakken-disk/krakken_logo.png",
        "/usr/share/icons/hicolor/64x64/apps/krakken-disk.svg",
        path1,
        path2,
        "krakken-disk.svg",
        "krakken-disk-v4.5.0-gtk4/krakken-disk.svg",
        "krakken-disk.png",
        NULL
    };
    
    for (int i = 0; paths[i] != NULL; i++) {
        if (g_file_test(paths[i], G_FILE_TEST_EXISTS)) {
            logo = gdk_pixbuf_new_from_file_at_scale(paths[i], size, size, TRUE, &error);
            if (logo) break;
            if (error) {
                g_error_free(error);
                error = NULL;
            }
        }
    }
    
    g_free(cwd);
    g_free(path_logo1);
    g_free(path_logo2);
    g_free(path1);
    g_free(path2);
    
    return logo;
}




typedef struct {
    GtkWidget *splash;
    GtkWidget *main_window;
    GtkWidget *progress;
    int ticks;
} SplashTimeoutData;

static gboolean on_splash_timeout(gpointer data) {
    SplashTimeoutData *std = (SplashTimeoutData *)data;
    std->ticks++;
    
    /* 25 ticks of 100ms = 2.5 seconds */
    double fraction = (double)std->ticks / 25.0;
    if (fraction > 1.0) fraction = 1.0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(std->progress), fraction);
    
    if (std->ticks >= 25) {
        /* Destroy splash window */
        gtk_widget_destroy(std->splash);
        
        /* Show main window */
        gtk_widget_show_all(std->main_window);
        
        g_free(std);
        return FALSE; /* Stop timeout */
    }
    return TRUE; /* Continue timeout */
}

/* Activate callback - build GUI */
static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;
    AppState *app_state = g_malloc(sizeof(AppState));
    app_state->show_password = 0;
    app_state->current_volume = NULL;

    /* Apply modern CSS styling */
    GtkCssProvider *css_provider = gtk_css_provider_new();
    const gchar *css_data = 
        "window, dialog {\n"
        "    background-color: #080b10;\n"
        "    color: #f0f6fc;\n"
        "    font-family: 'Ubuntu', 'DejaVu Sans', 'Liberation Sans', 'Segoe UI', sans-serif;\n"
        "}\n"
        ".sidebar {\n"
        "    background-color: #05070a;\n"
        "    border-right: 1px solid #1f242c;\n"
        "}\n"
        ".main-content {\n"
        "    background-color: #080b10;\n"
        "}\n"
        ".card {\n"
        "    background-color: #0d1117;\n"
        "    border: 1px solid #21262d;\n"
        "    border-radius: 8px;\n"
        "    padding: 14px;\n"
        "}\n"
        ".card-title {\n"
        "    font-size: 11px;\n"
        "    font-weight: bold;\n"
        "    color: #00ffcc;\n"
        "    letter-spacing: 1.2px;\n"
        "    margin-bottom: 8px;\n"
        "}\n"
        ".brand-title {\n"
        "    font-weight: 800;\n"
        "    font-size: 15px;\n"
        "    color: #00ffcc;\n"
        "    letter-spacing: 1.5px;\n"
        "}\n"
        ".brand-subtitle {\n"
        "    font-size: 9px;\n"
        "    color: #8b949e;\n"
        "    letter-spacing: 1px;\n"
        "}\n"
        ".telemetry-label {\n"
        "    font-size: 11px;\n"
        "    color: #8b949e;\n"
        "    font-weight: bold;\n"
        "}\n"
        ".telemetry-value {\n"
        "    font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace;\n"
        "    font-size: 11px;\n"
        "    color: #f0f6fc;\n"
        "}\n"
        "entry {\n"
        "    background-color: #05070a;\n"
        "    color: #ffffff;\n"
        "    border: 1px solid #21262d;\n"
        "    border-radius: 6px;\n"
        "    padding: 6px 10px;\n"
        "    caret-color: #00ffcc;\n"
        "    transition: all 0.2s ease;\n"
        "}\n"
        "entry:focus {\n"
        "    border-color: #00ffcc;\n"
        "}\n"
        "button {\n"
        "    background-color: #161b22;\n"
        "    color: #c9d1d9;\n"
        "    border: 1px solid #30363d;\n"
        "    border-radius: 6px;\n"
        "    padding: 6px 10px;\n"
        "    font-weight: bold;\n"
        "    transition: all 0.2s ease;\n"
        "}\n"
        "button:hover {\n"
        "    background-color: #21262d;\n"
        "    border-color: #8b949e;\n"
        "    color: #ffffff;\n"
        "}\n"
        "button:active {\n"
        "    background-color: #30363d;\n"
        "}\n"
        ".btn-cyan {\n"
        "    background: linear-gradient(135deg, #00ffcc, #00b386);\n"
        "    color: #05070a;\n"
        "    border: none;\n"
        "    font-weight: 800;\n"
        "}\n"
        ".btn-cyan:hover {\n"
        "    background: linear-gradient(135deg, #33ffd6, #00cca3);\n"
        "    color: #05070a;\n"
        "}\n"
        ".btn-red {\n"
        "    background-color: #211315;\n"
        "    color: #f85149;\n"
        "    border: 1px solid #f85149;\n"
        "}\n"
        ".btn-red:hover {\n"
        "    background-color: #f85149;\n"
        "    color: #ffffff;\n"
        "}\n"
        "progressbar > trough {\n"
        "    background-color: #161b22;\n"
        "    border-radius: 4px;\n"
        "    border: 1px solid #21262d;\n"
        "}\n"
        "progressbar > progress {\n"
        "    background: linear-gradient(90deg, #00ffcc, #00b386);\n"
        "    border-radius: 3px;\n"
        "}\n"
        "label.status {\n"
        "    font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace;\n"
        "    font-size: 11px;\n"
        "    color: #00ffcc;\n"
        "}\n"
        ".splash-window {\n"
        "    background-color: #050505;\n"
        "    border: 2px solid #00ffcc;\n"
        "    border-radius: 12px;\n"
        "}\n"
        ".splash-loading {\n"
        "    font-size: 1.2em;\n"
        "    font-weight: bold;\n"
        "    color: #00ffcc;\n"
        "    font-family: 'Ubuntu', sans-serif;\n"
        "}";

    gtk_css_provider_load_from_data(css_provider, css_data, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                                              GTK_STYLE_PROVIDER(css_provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    /* Main window */
    app_state->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(app_state->window), APP_TITLE);
    gtk_window_set_default_size(GTK_WINDOW(app_state->window), 880, 440);
    gtk_window_set_position(GTK_WINDOW(app_state->window), GTK_WIN_POS_CENTER);

    /* Set taskbar icon */
    GdkPixbuf *icon = load_app_logo(64);
    if (icon) {
        gtk_window_set_icon(GTK_WINDOW(app_state->window), icon);
        g_object_unref(icon);
    }

    /* Modern HeaderBar */
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Krakken-Disk");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "v4.5.0 \xe2\x80\xa2 Secure Volume Manager");
    gtk_window_set_titlebar(GTK_WINDOW(app_state->window), header);

    /* Main layout container (Horizontal) */
    GtkWidget *main_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_add(GTK_CONTAINER(app_state->window), main_hbox);

    /* --- Sidebar Pane --- */
    GtkWidget *sidebar_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(sidebar_vbox, 260, -1);
    gtk_style_context_add_class(gtk_widget_get_style_context(sidebar_vbox), "sidebar");
    gtk_box_pack_start(GTK_BOX(main_hbox), sidebar_vbox, FALSE, FALSE, 0);

    /* Brand Header */
    GtkWidget *brand_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_halign(brand_box, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), brand_box, FALSE, FALSE, 8);

    GtkWidget *logo_img = NULL;
    GdkPixbuf *logo_pb = load_app_logo(128);
    if (logo_pb) {
        logo_img = gtk_image_new_from_pixbuf(logo_pb);
        g_object_unref(logo_pb);
    } else {
        logo_img = gtk_image_new_from_icon_name("applications-system", GTK_ICON_SIZE_DIALOG);
    }
    gtk_box_pack_start(GTK_BOX(brand_box), logo_img, FALSE, FALSE, 0);

    GtkWidget *lbl_brand_title = gtk_label_new("KRAKKEN-DISK");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_brand_title), "brand-title");
    gtk_box_pack_start(GTK_BOX(brand_box), lbl_brand_title, FALSE, FALSE, 0);

    GtkWidget *lbl_brand_subtitle = gtk_label_new("POST-QUANTUM SHIELD");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_brand_subtitle), "brand-subtitle");
    gtk_box_pack_start(GTK_BOX(brand_box), lbl_brand_subtitle, FALSE, FALSE, 0);

    /* Separator */
    GtkWidget *sep_sidebar = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_opacity(sep_sidebar, 0.2);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), sep_sidebar, FALSE, FALSE, 4);

    /* Telemetry Card */
    GtkWidget *telemetry_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(telemetry_card), "card");
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), telemetry_card, FALSE, FALSE, 0);

    GtkWidget *lbl_telem_title = gtk_label_new("SYSTEM TELEMETRY");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_telem_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_telem_title), 0.0);
    gtk_box_pack_start(GTK_BOX(telemetry_card), lbl_telem_title, FALSE, FALSE, 0);

    GtkWidget *telem_grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(telem_grid), 8);
    gtk_grid_set_row_spacing(GTK_GRID(telem_grid), 6);
    gtk_box_pack_start(GTK_BOX(telemetry_card), telem_grid, TRUE, TRUE, 0);

    // Row 0: Volume Path
    GtkWidget *lbl_path_tag = gtk_label_new("VOLUME:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_path_tag), "telemetry-label");
    gtk_label_set_xalign(GTK_LABEL(lbl_path_tag), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), lbl_path_tag, 0, 0, 1, 1);

    app_state->lbl_telemetry_path = gtk_label_new("None");
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->lbl_telemetry_path), "telemetry-value");
    gtk_label_set_xalign(GTK_LABEL(app_state->lbl_telemetry_path), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(app_state->lbl_telemetry_path), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(app_state->lbl_telemetry_path, TRUE);
    gtk_grid_attach(GTK_GRID(telem_grid), app_state->lbl_telemetry_path, 1, 0, 1, 1);

    // Row 1: Crypto state
    GtkWidget *lbl_lock_tag = gtk_label_new("DECRYPT:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_lock_tag), "telemetry-label");
    gtk_label_set_xalign(GTK_LABEL(lbl_lock_tag), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), lbl_lock_tag, 0, 1, 1, 1);

    app_state->lbl_telemetry_lock = gtk_label_new("LOCKED");
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->lbl_telemetry_lock), "telemetry-value");
    gtk_label_set_xalign(GTK_LABEL(app_state->lbl_telemetry_lock), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), app_state->lbl_telemetry_lock, 1, 1, 1, 1);

    // Row 2: Mount status
    GtkWidget *lbl_mount_tag = gtk_label_new("MOUNT:");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_mount_tag), "telemetry-label");
    gtk_label_set_xalign(GTK_LABEL(lbl_mount_tag), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), lbl_mount_tag, 0, 2, 1, 1);

    app_state->lbl_telemetry_mount = gtk_label_new("INACTIVE");
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->lbl_telemetry_mount), "telemetry-value");
    gtk_label_set_xalign(GTK_LABEL(app_state->lbl_telemetry_mount), 0.0);
    gtk_grid_attach(GTK_GRID(telem_grid), app_state->lbl_telemetry_mount, 1, 2, 1, 1);

    /* Security Credentials Card */
    GtkWidget *security_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(security_card), "card");
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), security_card, FALSE, FALSE, 0);

    GtkWidget *lbl_sec_title = gtk_label_new("CREDENTIALS");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_sec_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_sec_title), 0.0);
    gtk_box_pack_start(GTK_BOX(security_card), lbl_sec_title, FALSE, FALSE, 0);

    app_state->password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(app_state->password_entry), FALSE);
    gtk_entry_set_invisible_char(GTK_ENTRY(app_state->password_entry), '*');
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state->password_entry), "Password");
    gtk_box_pack_start(GTK_BOX(security_card), app_state->password_entry, FALSE, FALSE, 2);

    app_state->show_password_check = gtk_check_button_new_with_label("Reveal characters");
    g_signal_connect(app_state->show_password_check, "toggled", G_CALLBACK(on_toggle_password), app_state);
    gtk_box_pack_start(GTK_BOX(security_card), app_state->show_password_check, FALSE, FALSE, 0);

    /* Sidebar Spacer */
    GtkWidget *sidebar_spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), sidebar_spacer, TRUE, TRUE, 0);

    /* Sidebar Footer Buttons */
    GtkWidget *sidebar_footer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(sidebar_footer, GTK_ALIGN_FILL);
    gtk_box_pack_start(GTK_BOX(sidebar_vbox), sidebar_footer, FALSE, FALSE, 4);

    GtkWidget *about_btn = gtk_button_new_with_label("About");
    gtk_button_set_image(GTK_BUTTON(about_btn), gtk_image_new_from_icon_name("help-about", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(about_btn), TRUE);
    gtk_widget_set_hexpand(about_btn, TRUE);
    g_signal_connect(about_btn, "clicked", G_CALLBACK(on_about_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(sidebar_footer), about_btn, TRUE, TRUE, 0);

    GtkWidget *quit_btn = gtk_button_new_with_label("Exit");
    gtk_button_set_image(GTK_BUTTON(quit_btn), gtk_image_new_from_icon_name("application-exit", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(quit_btn), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(quit_btn), "btn-red");
    gtk_widget_set_hexpand(quit_btn, TRUE);
    g_signal_connect(quit_btn, "clicked", G_CALLBACK(on_quit_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(sidebar_footer), quit_btn, TRUE, TRUE, 0);


    /* --- Main Content Pane --- */
    GtkWidget *content_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(content_vbox), "main-content");
    gtk_container_set_border_width(GTK_CONTAINER(content_vbox), 16);
    gtk_box_pack_start(GTK_BOX(main_hbox), content_vbox, TRUE, TRUE, 0);

    /* Volume Target File Card */
    GtkWidget *target_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(target_card), "card");
    gtk_box_pack_start(GTK_BOX(content_vbox), target_card, FALSE, FALSE, 0);

    GtkWidget *lbl_target_title = gtk_label_new("ENCRYPTED VOLUME FILE");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_target_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_target_title), 0.0);
    gtk_box_pack_start(GTK_BOX(target_card), lbl_target_title, FALSE, FALSE, 0);

    GtkWidget *target_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(target_card), target_hbox, TRUE, TRUE, 0);

    app_state->volume_path_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state->volume_path_entry), "Select location for volume file...");
    gtk_widget_set_hexpand(app_state->volume_path_entry, TRUE);
    g_signal_connect(app_state->volume_path_entry, "changed", G_CALLBACK(on_volume_path_changed), app_state);
    gtk_box_pack_start(GTK_BOX(target_hbox), app_state->volume_path_entry, TRUE, TRUE, 0);

    GtkWidget *btn_browse = gtk_button_new_from_icon_name("folder-open", GTK_ICON_SIZE_BUTTON);
    gtk_widget_set_tooltip_text(btn_browse, "Browse volume file...");
    g_signal_connect(btn_browse, "clicked", G_CALLBACK(on_browse_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(target_hbox), btn_browse, FALSE, FALSE, 0);


    /* Middle operations section (Side-by-side Cards) */
    GtkWidget *ops_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous(GTK_BOX(ops_hbox), TRUE);
    gtk_box_pack_start(GTK_BOX(content_vbox), ops_hbox, TRUE, TRUE, 0);

    /* Volume Control Card */
    GtkWidget *ctrl_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctrl_card), "card");
    gtk_box_pack_start(GTK_BOX(ops_hbox), ctrl_card, TRUE, TRUE, 0);

    GtkWidget *lbl_ctrl_title = gtk_label_new("VOLUME CONTROL");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_ctrl_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_ctrl_title), 0.0);
    gtk_box_pack_start(GTK_BOX(ctrl_card), lbl_ctrl_title, FALSE, FALSE, 0);

    GtkWidget *btn_row1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(btn_row1), TRUE);
    gtk_box_pack_start(GTK_BOX(ctrl_card), btn_row1, TRUE, TRUE, 0);

    GtkWidget *open_btn = gtk_button_new_with_label("Open");
    gtk_button_set_image(GTK_BUTTON(open_btn), gtk_image_new_from_icon_name("document-open", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(open_btn), TRUE);
    g_signal_connect(open_btn, "clicked", G_CALLBACK(on_open_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row1), open_btn, TRUE, TRUE, 0);

    GtkWidget *close_btn = gtk_button_new_with_label("Close");
    gtk_button_set_image(GTK_BUTTON(close_btn), gtk_image_new_from_icon_name("window-close", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(close_btn), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(close_btn), "btn-red");
    g_signal_connect(close_btn, "clicked", G_CALLBACK(on_close_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row1), close_btn, TRUE, TRUE, 0);

    GtkWidget *btn_row2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(btn_row2), TRUE);
    gtk_box_pack_start(GTK_BOX(ctrl_card), btn_row2, TRUE, TRUE, 0);

    GtkWidget *mount_btn = gtk_button_new_with_label("Mount");
    gtk_button_set_image(GTK_BUTTON(mount_btn), gtk_image_new_from_icon_name("drive-harddisk", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(mount_btn), TRUE);
    g_signal_connect(mount_btn, "clicked", G_CALLBACK(on_mount_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row2), mount_btn, TRUE, TRUE, 0);

    GtkWidget *unmount_btn = gtk_button_new_with_label("Unmount");
    gtk_button_set_image(GTK_BUTTON(unmount_btn), gtk_image_new_from_icon_name("media-eject", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(unmount_btn), TRUE);
    g_signal_connect(unmount_btn, "clicked", G_CALLBACK(on_unmount_volume_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(btn_row2), unmount_btn, TRUE, TRUE, 0);

    app_state->btn_check_space = gtk_button_new_with_label("Storage Status");
    gtk_button_set_image(GTK_BUTTON(app_state->btn_check_space), gtk_image_new_from_icon_name("dialog-information", GTK_ICON_SIZE_BUTTON));
    gtk_button_set_always_show_image(GTK_BUTTON(app_state->btn_check_space), TRUE);
    gtk_widget_set_sensitive(app_state->btn_check_space, FALSE);
    g_signal_connect(app_state->btn_check_space, "clicked", G_CALLBACK(on_check_space_clicked), app_state);
    gtk_box_pack_start(GTK_BOX(ctrl_card), app_state->btn_check_space, TRUE, TRUE, 0);


    /* New Volume Creator Card */
    GtkWidget *create_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(create_card), "card");
    gtk_box_pack_start(GTK_BOX(ops_hbox), create_card, TRUE, TRUE, 0);

    GtkWidget *lbl_create_title = gtk_label_new("NEW VOLUME CREATION");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_create_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_create_title), 0.0);
    gtk_box_pack_start(GTK_BOX(create_card), lbl_create_title, FALSE, FALSE, 0);

    GtkWidget *lbl_size_desc = gtk_label_new("Specify target size in MB:");
    gtk_widget_set_halign(lbl_size_desc, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(create_card), lbl_size_desc, FALSE, FALSE, 2);

    app_state->volume_size_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state->volume_size_entry), "Size (MB)");
    gtk_box_pack_start(GTK_BOX(create_card), app_state->volume_size_entry, FALSE, FALSE, 0);

    /* Spacer to push Create button to bottom */
    GtkWidget *create_spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start(GTK_BOX(create_card), create_spacer, TRUE, TRUE, 0);

    GtkWidget *create_btn = gtk_button_new_with_label("Create Volume");
    GtkWidget *create_icon = gtk_image_new_from_icon_name("document-new", GTK_ICON_SIZE_BUTTON);
    gtk_button_set_image(GTK_BUTTON(create_btn), create_icon);
    gtk_button_set_always_show_image(GTK_BUTTON(create_btn), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(create_btn), "btn-cyan");
    g_signal_connect(create_btn, "clicked", G_CALLBACK(on_create_volume_clicked), app_state);
    gtk_box_pack_end(GTK_BOX(create_card), create_btn, FALSE, FALSE, 0);


    /* Console status card */
    GtkWidget *console_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_style_context_add_class(gtk_widget_get_style_context(console_card), "card");
    gtk_box_pack_start(GTK_BOX(content_vbox), console_card, FALSE, FALSE, 0);

    GtkWidget *lbl_console_title = gtk_label_new("SYSTEM STATUS CONSOLE");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_console_title), "card-title");
    gtk_label_set_xalign(GTK_LABEL(lbl_console_title), 0.0);
    gtk_box_pack_start(GTK_BOX(console_card), lbl_console_title, FALSE, FALSE, 0);

    app_state->status_label = gtk_label_new("System Ready");
    gtk_label_set_xalign(GTK_LABEL(app_state->status_label), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(app_state->status_label), "status");
    gtk_box_pack_start(GTK_BOX(console_card), app_state->status_label, FALSE, FALSE, 2);

    app_state->progress_bar = gtk_progress_bar_new();
    gtk_widget_set_size_request(app_state->progress_bar, -1, 6);
    gtk_box_pack_start(GTK_BOX(console_card), app_state->progress_bar, FALSE, FALSE, 0);

    g_object_set_data(G_OBJECT(app_state->window), "app-state", app_state);

    /* Initialize telemetry data labels */
    update_telemetry(app_state);

    /* Create Splash Screen */
    GtkWidget *splash = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_decorated(GTK_WINDOW(splash), FALSE);
    gtk_window_set_position(GTK_WINDOW(splash), GTK_WIN_POS_CENTER);
    gtk_window_set_default_size(GTK_WINDOW(splash), 420, 460);
    
    GtkStyleContext *splash_context = gtk_widget_get_style_context(splash);
    gtk_style_context_add_class(splash_context, "splash-window");
    
    GtkWidget *splash_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(splash), splash_box);
    gtk_container_set_border_width(GTK_CONTAINER(splash_box), 20);
    
    /* Dynamically resolve krakken_splash.png path */
    char *splash_path = NULL;
    char *cwd = g_get_current_dir();
    char *path1 = g_build_filename(cwd, "krakken_splash.png", NULL);
    char *path2 = g_build_filename(cwd, "krakken-disk-v4.5.0-gtk4", "krakken_splash.png", NULL);
    const char *splash_paths[] = {
        path1,
        path2,
        "krakken_splash.png",
        "krakken-disk-v4.5.0-gtk4/krakken_splash.png",
        "/usr/share/krakken-disk/krakken_splash.png",
        "/usr/local/share/krakken-disk/krakken_splash.png",
        NULL
    };
    for (int i = 0; splash_paths[i] != NULL; i++) {
        if (g_file_test(splash_paths[i], G_FILE_TEST_EXISTS)) {
            splash_path = g_strdup(splash_paths[i]);
            break;
        }
    }
    g_free(cwd);
    g_free(path1);
    g_free(path2);

    GdkPixbuf *splash_pb = NULL;
    if (splash_path) {
        splash_pb = gdk_pixbuf_new_from_file_at_scale(splash_path, 340, 340, TRUE, NULL);
        g_free(splash_path);
    } else {
        splash_pb = gdk_pixbuf_new_from_file_at_scale("krakken_splash.png", 340, 340, TRUE, NULL);
    }
    
    GtkWidget *splash_img;
    if (splash_pb) {
        splash_img = gtk_image_new_from_pixbuf(splash_pb);
        g_object_unref(splash_pb);
    } else {
        splash_img = gtk_image_new_from_icon_name("image-missing", GTK_ICON_SIZE_DIALOG);
    }
    gtk_box_pack_start(GTK_BOX(splash_box), splash_img, TRUE, TRUE, 5);
    
    GtkWidget *loading_label = gtk_label_new("(Loading...)");
    gtk_style_context_add_class(gtk_widget_get_style_context(loading_label), "splash-loading");
    gtk_box_pack_start(GTK_BOX(splash_box), loading_label, FALSE, FALSE, 5);
    
    GtkWidget *splash_progress = gtk_progress_bar_new();
    gtk_widget_set_size_request(splash_progress, 340, 6);
    gtk_box_pack_start(GTK_BOX(splash_box), splash_progress, FALSE, FALSE, 10);
    
    gtk_widget_show_all(splash);
    
    SplashTimeoutData *std = g_malloc(sizeof(SplashTimeoutData));
    std->splash = splash;
    std->main_window = app_state->window;
    std->progress = splash_progress;
    std->ticks = 0;
    
    g_timeout_add(100, on_splash_timeout, std);
}

/* Cleanup callback */
static void on_shutdown(GtkApplication *app, gpointer user_data) {
    (void)user_data;
    GtkWindow *window = gtk_application_get_active_window(app);
    if (window) {
        AppState *app_state = g_object_get_data(G_OBJECT(window), "app-state");
        if (app_state) {
            if (app_state->current_volume) {
                if (app_state->current_volume->is_open) {
                    if (app_state->current_volume->vfs.is_mounted) {
                        stop_fuse_mount(app_state->current_volume);
                        volume_unmount(app_state->current_volume);
                    }
                    volume_close(app_state->current_volume, NULL, NULL);
                    free(app_state->current_volume);
                }
            }
            g_free(app_state);
        }
    }
}

#include <time.h>

#define SECRET_KEY "Krakken-Disk-Super-Secret-Key-2026"

/* Built-in SHA-256 engine for License/Trial Validation */
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} SHA256_CTX_LIC;

static const unsigned int k_lic[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform_lic(SHA256_CTX_LIC *ctx, const unsigned char data[]) {
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k_lic[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init_lic(SHA256_CTX_LIC *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update_lic(SHA256_CTX_LIC *ctx, const unsigned char data[], size_t len) {
    unsigned int i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform_lic(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final_lic(SHA256_CTX_LIC *ctx, unsigned char hash[]) {
    unsigned int i;

    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform_lic(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[56] = ctx->bitlen >> 56;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[63] = ctx->bitlen;
    sha256_transform_lic(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

static void sha256_hex_lic(const char *data, size_t len, char *hex_output) {
    SHA256_CTX_LIC ctx;
    unsigned char hash[32];
    sha256_init_lic(&ctx);
    sha256_update_lic(&ctx, (const unsigned char*)data, len);
    sha256_final_lic(&ctx, hash);
    for (int i = 0; i < 32; i++) {
        sprintf(hex_output + (i * 2), "%02x", hash[i]);
    }
    hex_output[64] = '\0';
}

/* License & Trial Validation Helpers */
static int verify_license_file(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) return 0;

    char line[256];
    char customer[256] = {0};
    char exp_date[64] = {0};
    char signature[128] = {0};

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "CUSTOMER:", 9) == 0) {
            char *val = line + 9;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(customer)) {
                strcpy(customer, val);
            }
        } else if (strncmp(line, "EXPIRATION_DATE:", 16) == 0) {
            char *val = line + 16;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(exp_date)) {
                strcpy(exp_date, val);
            }
        } else if (strncmp(line, "SIGNATURE:", 10) == 0) {
            char *val = line + 10;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(signature)) {
                strcpy(signature, val);
            }
        }
    }
    fclose(file);

    if (strlen(exp_date) == 0 || strlen(signature) == 0) {
        return 0;
    }

    char input_for_hash[512];
    if (strlen(customer) > 0) {
        snprintf(input_for_hash, sizeof(input_for_hash), "%s:%s:%s", customer, exp_date, SECRET_KEY);
    } else {
        snprintf(input_for_hash, sizeof(input_for_hash), "%s%s", exp_date, SECRET_KEY);
    }
    char expected_sig[65];
    sha256_hex_lic(input_for_hash, strlen(input_for_hash), expected_sig);

    if (strcmp(signature, expected_sig) != 0) {
        return 0;
    }

    int exp_year = 0, exp_month = 0, exp_day = 0;
    if (sscanf(exp_date, "%d-%d-%d", &exp_year, &exp_month, &exp_day) != 3) {
        return 0;
    }

    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    int cur_year = tm_info->tm_year + 1900;
    int cur_month = tm_info->tm_mon + 1;
    int cur_day = tm_info->tm_mday;

    if (cur_year < exp_year) return 1;
    if (cur_year == exp_year) {
        if (cur_month < exp_month) return 1;
        if (cur_month == exp_month) {
            if (cur_day <= exp_day) return 1;
        }
    }

    return 0;
}

static int get_trial_tries_left(const char *state_path) {
    FILE *file = fopen(state_path, "r");
    if (!file) {
        return 3;
    }

    char line[256];
    int tries = -1;
    char hash_str[128] = {0};

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "TRIES:", 6) == 0) {
            tries = atoi(line + 6);
        } else if (strncmp(line, "HASH:", 5) == 0) {
            char *val = line + 5;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(hash_str)) {
                strcpy(hash_str, val);
            }
        }
    }
    fclose(file);

    if (tries < 0 || tries > 3 || strlen(hash_str) == 0) {
        return 0;
    }

    char hash_input[128];
    snprintf(hash_input, sizeof(hash_input), "%d%s", tries, SECRET_KEY);
    char expected_hash[65];
    sha256_hex_lic(hash_input, strlen(hash_input), expected_hash);

    if (strcmp(hash_str, expected_hash) != 0) {
        return 0;
    }

    return tries;
}

static void set_trial_tries_left(const char *state_path, int tries) {
    if (tries < 0) tries = 0;
    if (tries > 3) tries = 3;

    char hash_input[128];
    snprintf(hash_input, sizeof(hash_input), "%d%s", tries, SECRET_KEY);
    char hash_output[65];
    sha256_hex_lic(hash_input, strlen(hash_input), hash_output);

    FILE *file = fopen(state_path, "w");
    if (file) {
        fprintf(file, "TRIES:%d\n", tries);
        fprintf(file, "HASH:%s\n", hash_output);
        fclose(file);
    }
}

struct LicenseDialogState {
    int code;
    GtkWidget *dialog;
    char *path_buffer;
    size_t path_max;
    gboolean loop;
};

static void on_license_exit_clicked(GtkButton *button, gpointer data) {
    (void)button;
    struct LicenseDialogState *state = (struct LicenseDialogState*)data;
    if (state->code == 0) {
        state->code = 0;
    }
    state->loop = FALSE;
}

static void on_license_trial_clicked(GtkButton *button, gpointer data) {
    (void)button;
    struct LicenseDialogState *state = (struct LicenseDialogState*)data;
    state->code = 1;
    state->loop = FALSE;
}

static void on_license_load_clicked(GtkButton *button, gpointer data) {
    (void)button;
    struct LicenseDialogState *state = (struct LicenseDialogState*)data;

    GtkWidget *chooser = gtk_file_chooser_dialog_new(
        "Select License File",
        GTK_WINDOW(state->dialog),
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL
    );

    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Text Files (*.txt)");
    gtk_file_filter_add_pattern(filter, "*.txt");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter);

    if (gtk_dialog_run(GTK_DIALOG(chooser)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
        if (filename) {
            strncpy(state->path_buffer, filename, state->path_max - 1);
            state->path_buffer[state->path_max - 1] = '\0';
            g_free(filename);

            if (verify_license_file(state->path_buffer)) {
                state->code = 2;
                state->loop = FALSE;
            } else {
                GtkWidget *err_dialog = gtk_message_dialog_new(
                    GTK_WINDOW(state->dialog),
                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                    GTK_MESSAGE_ERROR,
                    GTK_BUTTONS_OK,
                    "Invalid license file! Please select a valid 1-year Krakken-Disk license."
                );
                gtk_dialog_run(GTK_DIALOG(err_dialog));
                gtk_widget_destroy(err_dialog);
            }
        }
    }
    gtk_widget_destroy(chooser);
}

static int __attribute__((unused)) check_license_verification(void) {
    char license_save_path[1024];
    char state_path[1024];
    char *home = getenv("HOME");
    if (!home) return 0;

    snprintf(license_save_path, sizeof(license_save_path), "%s/.krakken_license", home);
    snprintf(state_path, sizeof(state_path), "%s/.krakken_state", home);

    if (verify_license_file(license_save_path)) {
        return 1;
    }

    int tries_left = get_trial_tries_left(state_path);

    char selected_path[1024] = {0};
    struct LicenseDialogState dstate = {0, NULL, selected_path, sizeof(selected_path), TRUE};

    GtkWidget *dialog = gtk_dialog_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "License Activation - Krakken-Disk");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 500, 320);
    gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);

    dstate.dialog = dialog;

    GtkCssProvider *cp = gtk_css_provider_new();
    gtk_css_provider_load_from_data(cp,
        "dialog { background-color: #0a0a0a; color: #e0e0e0; font-family: 'Segoe UI', 'Roboto', sans-serif; }\n"
        "box { background-color: #0a0a0a; }\n"
        ".dialog-card { background-color: #121212; border: 1px solid #222; border-radius: 8px; padding: 15px; }\n"
        ".dialog-title { font-size: 18px; font-weight: bold; color: #ffffff; }\n"
        ".dialog-warning { font-size: 14px; font-weight: bold; color: #00ffcc; }\n"
        ".dialog-expired { font-size: 14px; font-weight: bold; color: #ff3333; }\n"
        ".action-btn { background-image: linear-gradient(to bottom right, #00ffcc, #00b386); color: #000000; font-weight: bold; border: none; border-radius: 6px; padding: 10px 20px; }\n"
        ".action-btn:hover { background-image: linear-gradient(to bottom right, #33ffd6, #00cca3); }\n"
        ".trial-btn { background-color: #1a1a1a; color: #e0e0e0; border: 1px solid #333; border-radius: 6px; padding: 10px 20px; font-weight: bold; }\n"
        ".trial-btn:hover { background-color: #252525; border-color: #00ffcc; color: #ffffff; }\n"
        ".exit-btn { background-image: linear-gradient(to bottom right, #ff3333, #b30000); color: #ffffff; font-weight: bold; border: none; border-radius: 6px; padding: 10px 20px; }\n"
        ".exit-btn:hover { background-image: linear-gradient(to bottom right, #ff6666, #e60000); }",
        -1, NULL);

    GtkStyleContext *dialog_context = gtk_widget_get_style_context(dialog);
    gtk_style_context_add_provider(dialog_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 25);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);

    /* Load logo from global or local path using existing load_app_logo helper */
    GdkPixbuf *pb = load_app_logo(64);
    GtkWidget *icon_img;
    if (pb) {
        icon_img = gtk_image_new_from_pixbuf(pb);
        g_object_unref(pb);
    } else {
        icon_img = gtk_image_new_from_icon_name("applications-system", GTK_ICON_SIZE_DIALOG);
    }
    gtk_box_pack_start(GTK_BOX(vbox), icon_img, FALSE, FALSE, 0);

    GtkWidget *lbl_title = gtk_label_new("Krakken-Disk Activation");
    GtkStyleContext *title_context = gtk_widget_get_style_context(lbl_title);
    gtk_style_context_add_class(title_context, "dialog-title");
    gtk_style_context_add_provider(title_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(vbox), lbl_title, FALSE, FALSE, 0);

    GtkWidget *msg_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkStyleContext *card_context = gtk_widget_get_style_context(msg_card);
    gtk_style_context_add_class(card_context, "dialog-card");
    gtk_style_context_add_provider(card_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(vbox), msg_card, TRUE, TRUE, 0);

    GtkWidget *lbl_status = gtk_label_new(NULL);
    GtkStyleContext *status_context = gtk_widget_get_style_context(lbl_status);
    gtk_style_context_add_provider(status_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *lbl_desc = gtk_label_new(NULL);
    gtk_label_set_justify(GTK_LABEL(lbl_desc), GTK_JUSTIFY_CENTER);
    gtk_label_set_line_wrap(GTK_LABEL(lbl_desc), TRUE);

    if (tries_left > 0) {
        char status_txt[128];
        snprintf(status_txt, sizeof(status_txt), "Trial Period Active: %d %s Left", tries_left, tries_left == 1 ? "Try" : "Tries");
        gtk_label_set_text(GTK_LABEL(lbl_status), status_txt);
        gtk_style_context_add_class(status_context, "dialog-warning");

        gtk_label_set_text(GTK_LABEL(lbl_desc),
            "Krakken-Disk Manager requires a valid 1-year license to run.\n"
            "You can choose to continue the trial, or load a license file (.txt).");
    } else {
        gtk_label_set_text(GTK_LABEL(lbl_status), "Trial Period Expired");
        gtk_style_context_add_class(status_context, "dialog-expired");

        gtk_label_set_text(GTK_LABEL(lbl_desc),
            "The trial period has expired. You can no longer run Krakken-Disk.\n"
            "Please select a valid license file (.txt) to continue using the software.");
    }

    gtk_box_pack_start(GTK_BOX(msg_card), lbl_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(msg_card), lbl_desc, TRUE, TRUE, 0);

    GtkWidget *btn_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(btn_hbox, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(vbox), btn_hbox, FALSE, FALSE, 5);

    GtkWidget *btn_exit = gtk_button_new_with_label("Exit");
    GtkStyleContext *exit_context = gtk_widget_get_style_context(btn_exit);
    gtk_style_context_add_class(exit_context, "exit-btn");
    gtk_style_context_add_provider(exit_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(btn_hbox), btn_exit, FALSE, FALSE, 0);

    GtkWidget *btn_trial = NULL;
    if (tries_left > 0) {
        btn_trial = gtk_button_new_with_label("Continue Trial");
        GtkStyleContext *trial_context = gtk_widget_get_style_context(btn_trial);
        gtk_style_context_add_class(trial_context, "trial-btn");
        gtk_style_context_add_provider(trial_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        gtk_box_pack_start(GTK_BOX(btn_hbox), btn_trial, FALSE, FALSE, 0);
    }

    GtkWidget *btn_load = gtk_button_new_with_label("Load License File");
    GtkStyleContext *load_context = gtk_widget_get_style_context(btn_load);
    gtk_style_context_add_class(load_context, "action-btn");
    gtk_style_context_add_provider(load_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(btn_hbox), btn_load, FALSE, FALSE, 0);

    g_signal_connect(btn_exit, "clicked", G_CALLBACK(on_license_exit_clicked), &dstate);
    g_signal_connect(dialog, "destroy", G_CALLBACK(on_license_exit_clicked), &dstate);
    if (btn_trial) {
        g_signal_connect(btn_trial, "clicked", G_CALLBACK(on_license_trial_clicked), &dstate);
    }
    g_signal_connect(btn_load, "clicked", G_CALLBACK(on_license_load_clicked), &dstate);

    gtk_widget_show_all(dialog);

    while (dstate.loop) {
        g_main_context_iteration(NULL, TRUE);
    }

    gtk_widget_destroy(dialog);
    g_object_unref(cp);

    if (dstate.code == 2) {
        FILE *src = fopen(selected_path, "r");
        if (src) {
            FILE *dest = fopen(license_save_path, "w");
            if (dest) {
                char ch;
                while ((ch = fgetc(src)) != EOF) {
                    fputc(ch, dest);
                }
                fclose(dest);
            }
            fclose(src);
        }

        GtkWidget *success_dialog = gtk_message_dialog_new(
            NULL,
            GTK_DIALOG_MODAL,
            GTK_MESSAGE_INFO,
            GTK_BUTTONS_OK,
            "License activated successfully! Thank you for choosing Krakken-Disk."
        );
        gtk_dialog_run(GTK_DIALOG(success_dialog));
        gtk_widget_destroy(success_dialog);

        return 1;
    } else if (dstate.code == 1) {
        tries_left--;
        set_trial_tries_left(state_path, tries_left);
        return 1;
    }

    return 0;
}

/* Create GUI */
int create_gui(int argc, char **argv) {
    gtk_init(&argc, &argv);

    GtkApplication *app;
    int status;
    
    app = gtk_application_new("org.krakken.disk", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    g_signal_connect(app, "shutdown", G_CALLBACK(on_shutdown), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    
    return status;
}
