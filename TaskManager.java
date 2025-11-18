import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Simple vanilla Java CLI "Task Manager" with CSV persistence.
 * ------------------------------------------------------------
 * Features:
 *  - Add/list/search/complete/delete tasks
 *  - Sort by due date, priority, or created time
 *  - Persist tasks to a local CSV file (./tasks.csv)
 *  - No external dependencies; works with "javac TaskManager.java && java TaskManager"
 *
 * Tips:
 *  - Dates use ISO-8601: YYYY-MM-DD (e.g., 2025-10-14)
 *  - Priorities: LOW, MEDIUM, HIGH, CRITICAL
 */
public class TaskManager {

    // ===== Domain types =====
    enum Priority {
        LOW, MEDIUM, HIGH, CRITICAL;

        static Priority parse(String s) {
            if (s == null) return MEDIUM;
            String norm = s.trim().toUpperCase(Locale.ROOT);
            for (Priority p : values()) {
                if (p.name().equals(norm)) return p;
            }
            throw new IllegalArgumentException("Unknown priority: " + s);
        }
    }

    static final class Task {
        final String id;                  // stable unique ID
        String title;
        String notes;
        Priority priority;
        LocalDate created;
        LocalDate due;                    // nullable
        boolean done;

        Task(String id,
             String title,
             String notes,
             Priority priority,
             LocalDate created,
             LocalDate due,
             boolean done) {
            this.id = id;
            this.title = title;
            this.notes = notes;
            this.priority = priority;
            this.created = created;
            this.due = due;
            this.done = done;
        }

        static Task newTask(String title, String notes, Priority priority, LocalDate due) {
            return new Task(
                    UUID.randomUUID().toString(),
                    title,
                    notes,
                    priority == null ? Priority.MEDIUM : priority,
                    LocalDate.now(),
                    due,
                    false
            );
        }

        @Override
        public String toString() {
            String d = (due == null) ? "-" : due.toString();
            return String.format("[%s] %s | prio=%s | due=%s | done=%s%s",
                    id.substring(0, 8),
                    title,
                    priority,
                    d,
                    done ? "yes" : "no",
                    (notes == null || notes.isBlank()) ? "" : " | notes=" + notes.replace('\n', ' ')
            );
        }
    }

    // ===== Storage: naive CSV (no commas in fields recommended) =====
    static final class TaskStore {
        private final Path file;
        private static final String HEADER = "id,title,notes,priority,created,due,done";
        private static final DateTimeFormatter DF = DateTimeFormatter.ISO_LOCAL_DATE;

        TaskStore(Path file) {
            this.file = file;
        }

        List<Task> load() throws IOException {
            List<Task> out = new ArrayList<>();
            if (!Files.exists(file)) {
                return out;
            }
            List<String> lines = Files.readAllLines(file);
            boolean first = true;
            for (String line : lines) {
                if (first) { first = false; continue; } // skip header
                if (line.isBlank()) continue;
                // Simple CSV: split by comma, allow empty token
                List<String> cells = splitCsv(line);
                if (cells.size() < 7) continue;
                String id = cells.get(0);
                String title = cells.get(1);
                String notes = nullOrBlankToNull(cells.get(2));
                Priority p = Priority.parse(cells.get(3));
                LocalDate created = parseDateOrNull(cells.get(4));
                LocalDate due = parseDateOrNull(cells.get(5));
                boolean done = Boolean.parseBoolean(cells.get(6));
                if (created == null) created = LocalDate.now();
                out.add(new Task(id, title, notes, p, created, due, done));
            }
            return out;
        }

        void save(List<Task> tasks) throws IOException {
            try (BufferedWriter bw = Files.newBufferedWriter(file)) {
                bw.write(HEADER);
                bw.newLine();
                for (Task t : tasks) {
                    bw.write(joinCsv(
                            t.id,
                            safe(t.title),
                            safe(nullToBlank(t.notes)),
                            t.priority.name(),
                            t.created.format(DF),
                            t.due == null ? "" : t.due.format(DF),
                            String.valueOf(t.done)
                    ));
                    bw.newLine();
                }
            }
        }

        private static List<String> splitCsv(String line) {
            // Minimal CSV splitter: no quoting support; commas split cells.
            List<String> res = new ArrayList<>();
            StringTokenizer st = new StringTokenizer(line, ",", true);
            StringBuilder cell = new StringBuilder();
            boolean lastWasComma = true;
            while (st.hasMoreTokens()) {
                String tok = st.nextToken();
                if (",".equals(tok)) {
                    res.add(cell.toString());
                    cell.setLength(0);
                    lastWasComma = true;
                } else {
                    cell.append(tok);
                    lastWasComma = false;
                }
            }
            if (!lastWasComma) {
                res.add(cell.toString());
            } else {
                // trailing comma -> empty last field
                res.add("");
            }
            return res;
        }

        private static String joinCsv(String... cells) {
            StringJoiner j = new StringJoiner(",");
            for (String c : cells) j.add(c == null ? "" : c);
            return j.toString();
        }

        private static String safe(String s) { return s == null ? "" : s.replace("\n", " ").trim(); }
        private static String nullToBlank(String s) { return s == null ? "" : s; }
        private static String nullOrBlankToNull(String s) { return (s == null || s.isBlank()) ? null : s; }
        private static LocalDate parseDateOrNull(String s) {
            if (s == null || s.isBlank()) return null;
            try { return LocalDate.parse(s, DF); }
            catch (DateTimeParseException e) { return null; }
        }
    }

    // ===== In-memory service =====
    static final class TaskService {
        private final List<Task> tasks;
        private final TaskStore store;

        TaskService(TaskStore store, List<Task> initial) {
            this.store = store;
            this.tasks = new ArrayList<>(initial);
        }

        Task add(String title, String notes, Priority p, LocalDate due) {
            Objects.requireNonNull(title, "title");
            Task t = Task.newTask(title.trim(), notes, p, due);
            tasks.add(t);
            persist();
            return t;
        }

        boolean deleteByShortId(String shortId) {
            Optional<Task> match = findByShortId(shortId);
            match.ifPresent(tasks::remove);
            persist();
            return match.isPresent();
        }

        boolean complete(String shortId) {
            Optional<Task> match = findByShortId(shortId);
            match.ifPresent(t -> t.done = true);
            persist();
            return match.isPresent();
        }

        List<Task> listSorted(Comparator<Task> cmp, boolean includeDone) {
            return tasks.stream()
                    .filter(t -> includeDone || !t.done)
                    .sorted(cmp)
                    .collect(Collectors.toList());
        }

        List<Task> search(String q) {
            String needle = q.toLowerCase(Locale.ROOT);
            return tasks.stream()
                    .filter(t -> (t.title != null && t.title.toLowerCase(Locale.ROOT).contains(needle)) ||
                                 (t.notes != null && t.notes.toLowerCase(Locale.ROOT).contains(needle)))
                    .sorted(Comparator.comparing((Task t) -> t.done)
                            .thenComparing(t -> t.due == null ? LocalDate.MAX : t.due))
                    .collect(Collectors.toList());
        }

        Optional<Task> findByShortId(String shortId) {
            return tasks.stream().filter(t -> t.id.startsWith(shortId)).findFirst();
        }

        void persist() {
            try { store.save(tasks); }
            catch (IOException e) {
                System.err.println("WARN: could not persist tasks: " + e.getMessage());
            }
        }
    }

    // ===== CLI =====
    private final BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
    private final PrintStream out = System.out;
    private final TaskService svc;

    private TaskManager(TaskService svc) {
        this.svc = svc;
    }

    public static void main(String[] args) {
        Path file = Paths.get("tasks.csv");
        TaskStore store = new TaskStore(file);
        List<Task> initial;
        try {
            initial = store.load();
        } catch (IOException e) {
            System.err.println("WARN: could not read tasks: " + e.getMessage());
            initial = new ArrayList<>();
        }
        TaskService svc = new TaskService(store, initial);
        TaskManager cli = new TaskManager(svc);
        cli.run();
    }

    private void run() {
        banner();
        help();
        while (true) {
            out.print("\n> ");
            String line = readLine();
            if (line == null) break;
            String cmd = line.trim();
            if (cmd.isEmpty()) continue;

            if (cmd.equalsIgnoreCase("exit") || cmd.equalsIgnoreCase("quit")) {
                out.println("Bye!");
                return;
            }

            try {
                handle(cmd);
            } catch (Exception e) {
                out.println("Error: " + e.getMessage());
            }
        }
    }

    private void handle(String cmd) {
        String lower = cmd.toLowerCase(Locale.ROOT);
        if (lower.startsWith("add ")) {
            doAdd(cmd.substring(4).trim());
        } else if (lower.equals("list") || lower.startsWith("list")) {
            doList(parseFlags(lower));
        } else if (lower.startsWith("search ")) {
            doSearch(cmd.substring(7).trim());
        } else if (lower.startsWith("done ")) {
            String id = cmd.substring(5).trim();
            if (svc.complete(id)) out.println("Marked " + id + " as done.");
            else out.println("No task starting with id: " + id);
        } else if (lower.startsWith("del ")) {
            String id = cmd.substring(4).trim();
            if (svc.deleteByShortId(id)) out.println("Deleted " + id + ".");
            else out.println("No task starting with id: " + id);
        } else if (lower.equals("help")) {
            help();
        } else {
            out.println("Unknown command. Type 'help' for options.");
        }
    }

    private EnumSet<ListFlag> parseFlags(String lowerCmd) {
        EnumSet<ListFlag> flags = EnumSet.noneOf(ListFlag.class);
        if (lowerCmd.contains("--all")) flags.add(ListFlag.SHOW_DONE);
        if (lowerCmd.contains("--by=due")) flags.add(ListFlag.SORT_DUE);
        else if (lowerCmd.contains("--by=prio")) flags.add(ListFlag.SORT_PRIO);
        else if (lowerCmd.contains("--by=created")) flags.add(ListFlag.SORT_CREATED);
        else flags.add(ListFlag.SORT_DEFAULT);
        return flags;
    }

    enum ListFlag { SHOW_DONE, SORT_DUE, SORT_PRIO, SORT_CREATED, SORT_DEFAULT }

    private void doList(EnumSet<ListFlag> flags) {
        boolean includeDone = flags.contains(ListFlag.SHOW_DONE);
        Comparator<Task> cmp;
        if (flags.contains(ListFlag.SORT_PRIO)) {
            cmp = Comparator.comparing((Task t) -> t.done)
                    .thenComparing((Task t) -> t.priority.ordinal())
                    .thenComparing(t -> t.due == null ? LocalDate.MAX : t.due);
        } else if (flags.contains(ListFlag.SORT_CREATED)) {
            cmp = Comparator.comparing((Task t) -> t.done)
                    .thenComparing((Task t) -> t.created)
                    .thenComparing(t -> t.due == null ? LocalDate.MAX : t.due);
        } else {
            // default: by due date
            cmp = Comparator.comparing((Task t) -> t.done)
                    .thenComparing(t -> t.due == null ? LocalDate.MAX : t.due)
                    .thenComparing((Task t) -> t.priority.ordinal());
        }
        List<Task> tasks = svc.listSorted(cmp, includeDone);
        if (tasks.isEmpty()) {
            out.println("(no tasks)");
            return;
        }
        out.println("Tasks:");
        for (Task t : tasks) {
            out.println("  " + t);
        }
    }

    private void doSearch(String q) {
        if (q.isBlank()) {
            out.println("Usage: search <text>");
            return;
        }
        List<Task> hits = svc.search(q);
        if (hits.isEmpty()) {
            out.println("(no matches)");
            return;
        }
        out.println("Matches:");
        for (Task t : hits) {
            out.println("  " + t);
        }
    }

    /**
     * add syntax:
     *   add "Title" [--prio=LOW|MEDIUM|HIGH|CRITICAL] [--due=YYYY-MM-DD] [--notes="text"]
     *
     * Quotes for title/notes are optional but recommended if spaces exist.
     */
    private void doAdd(String args) {
        if (args.isBlank()) {
            out.println("Usage: add \"Title\" [--prio=HIGH] [--due=2025-10-14] [--notes=\"...\"]");
            return;
        }
        String title = null;
        String notes = null;
        Priority prio = Priority.MEDIUM;
        LocalDate due = null;

        // crude parser: first token (maybe quoted) is the title; rest are flags
        Tokenizer t = new Tokenizer(args);
        if (t.hasNext()) {
            title = t.nextTokenPossiblyQuoted();
        }
        while (t.hasNext()) {
            String token = t.nextRaw();
            if (token.startsWith("--prio=")) {
                prio = Priority.parse(token.substring(7));
            } else if (token.startsWith("--due=")) {
                due = parseDate(token.substring(6));
            } else if (token.startsWith("--notes=")) {
                notes = stripQuotes(token.substring(8));
            } else {
                out.println("Ignoring unknown flag: " + token);
            }
        }

        if (title == null || title.isBlank()) {
            out.println("Title required.");
            return;
        }
        Task created = svc.add(title, notes, prio, due);
        out.println("Added: " + created);
    }

    private static LocalDate parseDate(String s) {
        try { return LocalDate.parse(s, DateTimeFormatter.ISO_LOCAL_DATE); }
        catch (DateTimeParseException e) { throw new IllegalArgumentException("Invalid date: " + s); }
    }

    // ===== Tiny token helper for quoted strings =====
    static final class Tokenizer {
        private final String src;
        private int i;

        Tokenizer(String src) {
            this.src = src;
            this.i = 0;
        }

        boolean hasNext() { skipWs(); return i < src.length(); }

        String nextRaw() {
            skipWs();
            int start = i;
            while (i < src.length() && !Character.isWhitespace(src.charAt(i))) i++;
            return src.substring(start, i);
        }

        String nextTokenPossiblyQuoted() {
            skipWs();
            if (i < src.length() && src.charAt(i) == '"') {
                return parseQuoted();
            }
            // unquoted until whitespace
            return nextRaw();
        }

        private String parseQuoted() {
            // assume starting at quote
            i++; // skip opening "
            StringBuilder sb = new StringBuilder();
            while (i < src.length()) {
                char c = src.charAt(i++);
                if (c == '"') break;
                if (c == '\\' && i < src.length()) {
                    char n = src.charAt(i++);
                    if (n == '"' || n == '\\') sb.append(n);
                    else { sb.append(c).append(n); }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private void skipWs() {
            while (i < src.length() && Character.isWhitespace(src.charAt(i))) i++;
        }
    }

    private static String stripQuotes(String s) {
        String t = s.trim();
        if (t.length() >= 2 && t.startsWith("\"") && t.endsWith("\"")) {
            return t.substring(1, t.length() - 1);
        }
        return t;
    }

    // ===== UI helpers =====
    private void banner() {
        out.println("======================================");
        out.println("       Task Manager (vanilla Java)    ");
        out.println("======================================");
        out.println("Data file: ./tasks.csv");
    }

    private void help() {
        out.println("\nCommands:");
        out.println("  add \"Title\" [--prio=LOW|MEDIUM|HIGH|CRITICAL] [--due=YYYY-MM-DD] [--notes=\"text\"]");
        out.println("  list [--all] [--by=due|prio|created]");
        out.println("  search <text>");
        out.println("  done <shortId>     (use first 8 chars shown in list)");
        out.println("  del <shortId>");
        out.println("  help | exit");
    }

    private String readLine() {
        try { return in.readLine(); }
        catch (IOException e) { return null; }
    }
}
