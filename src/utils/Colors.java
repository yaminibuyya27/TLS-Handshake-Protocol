package utils;

public class Colors {
    // ANSI color codes for terminal
    public static final String RESET = "\033[0m";
    public static final String BLUE = "\033[0;34m";
    public static final String MAGENTA = "\033[0;35m";
    public static final String CYAN = "\033[0;36m";

    // Bold colors
    public static final String BOLD_GREEN = "\033[1;32m";
    public static final String BOLD_RED = "\033[1;31m";
    public static final String BOLD_CYAN = "\033[1;36m";
    public static final String BOLD_MAGENTA = "\033[1;35m";

    public static String client(String msg) {
        return CYAN + "CLIENT: " + RESET + msg;
    }

    public static String server(String msg) {
        return MAGENTA + "SERVER: " + RESET + msg;
    }

    public static String success(String msg) {
        return BOLD_GREEN + "Success " + msg + RESET;
    }

    public static String error(String msg) {
        return BOLD_RED + "Got Error " + msg + RESET;
    }

    public static String info(String msg) {
        return BLUE + "Info " + msg + RESET;
    }
}