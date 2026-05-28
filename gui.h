#ifndef GUI_H
#define GUI_H

#include <gtk/gtk.h>
#include "volume.h"

/* Application state */
typedef struct {
    GtkWidget *window;
    GtkWidget *progress_bar;
    GtkWidget *status_label;
    GtkWidget *volume_path_entry;
    GtkWidget *volume_size_entry;
    GtkWidget *password_entry;
    GtkWidget *show_password_check;
    int show_password;
    GtkWidget *btn_check_space;
    volume_context_t *current_volume;
    GtkWidget *lbl_telemetry_path;
    GtkWidget *lbl_telemetry_lock;
    GtkWidget *lbl_telemetry_mount;
} AppState;

/* GUI functions */
int create_gui(int argc, char **argv);
void show_error_dialog(GtkWidget *parent, const char *message);
void show_info_dialog(GtkWidget *parent, const char *message);
void show_warning_dialog(GtkWidget *parent, const char *message);

#endif /* GUI_H */
