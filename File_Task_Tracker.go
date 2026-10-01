package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// ---------------------------------------------------------
// 1. DATA MODELS & JSON SERIALIZATION
// ---------------------------------------------------------

// Task represents an individual to-do item.
type Task struct {
	ID          int        `json:"id"`
	Title       string     `json:"title"`
	Completed   bool       `json:"completed"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ---------------------------------------------------------
// 2. FILE I/O OPERATIONS (os.ReadFile & os.WriteFile)
// ---------------------------------------------------------

// loadTasks reads the JSON file and deserializes tasks into memory.
func loadTasks(filename string) ([]Task, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		// If file doesn't exist yet, return an empty task list without error
		if errors.Is(err, os.ErrNotExist) {
			return []Task{}, nil
		}
		return nil, fmt.Errorf("could not read file '%s': %w", filename, err)
	}

	// Handle empty file edge case
	if len(strings.TrimSpace(string(data))) == 0 {
		return []Task{}, nil
	}

	var tasks []Task
	if err := json.Unmarshal(data, &tasks); err != nil {
		return nil, fmt.Errorf("corrupted JSON data in '%s': %w", filename, err)
	}

	return tasks, nil
}

// saveTasks serializes the tasks and writes them safely to disk.
func saveTasks(filename string, tasks []Task) error {
	// MarshalIndent formats the output with clean spacing for readability
	data, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode tasks to JSON: %w", err)
	}

	// 0644 gives Read/Write to the user, and Read to everyone else
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write to file '%s': %w", filename, err)
	}

	return nil
}

// ---------------------------------------------------------
// 3. TASK ACTIONS (Add, Complete, Delete, List)
// ---------------------------------------------------------

func addTask(tasks *[]Task, title string) {
	title = strings.TrimSpace(title)
	if title == "" {
		fmt.Println("❌ Error: Task title cannot be empty.")
		return
	}

	// Find next auto-incrementing ID
	nextID := 1
	for _, t := range *tasks {
		if t.ID >= nextID {
			nextID = t.ID + 1
		}
	}

	newTask := Task{
		ID:        nextID,
		Title:     title,
		Completed: false,
		CreatedAt: time.Now(),
	}

	*tasks = append(*tasks, newTask)
	fmt.Printf("✅ Added task #%d: \"%s\"\n", newTask.ID, newTask.Title)
}

func completeTask(tasks []Task, id int) bool {
	for i := range tasks {
		if tasks[i].ID == id {
			if tasks[i].Completed {
				fmt.Printf("ℹ️  Task #%d is already completed.\n", id)
				return false
			}
			now := time.Now()
			tasks[i].Completed = true
			tasks[i].CompletedAt = &now
			fmt.Printf("🎉 Task #%d marked as completed!\n", id)
			return true
		}
	}
	fmt.Printf("❌ Error: Task #%d not found.\n", id)
	return false
}

func deleteTask(tasks *[]Task, id int) bool {
	taskList := *tasks
	for i, t := range taskList {
		if t.ID == id {
			// Slice manipulation to remove item at index i
			*tasks = append(taskList[:i], taskList[i+1:]...)
			fmt.Printf("🗑️  Task #%d was deleted.\n", id)
			return true
		}
	}
	fmt.Printf("❌ Error: Task #%d not found.\n", id)
	return false
}

func listTasks(tasks []Task) {
	if len(tasks) == 0 {
		fmt.Println("📭 No tasks found! Use -add \"task description\" to get started.")
		return
	}

	// Uses standard library text/tabwriter for aligned, clean columns
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "STATUS\tID\tTASK\tCREATED")
	fmt.Fprintln(w, "------\t--\t----\t-------")

	for _, t := range tasks {
		status := "[ ]"
		if t.Completed {
			status = "[✓]"
		}
		timeStr := t.CreatedAt.Format("2006-01-02 15:04")
		fmt.Fprintf(w, "%s\t#%d\t%s\t%s\n", status, t.ID, t.Title, timeStr)
	}
	w.Flush()
}

// ---------------------------------------------------------
// 4. CLI FLAGS & ENTRY POINT
// ---------------------------------------------------------

func main() {
	// Define command-line flags
	addFlag := flag.String("add", "", "Add a new task: -add \"Buy groceries\"")
	listFlag := flag.Bool("list", false, "List all tasks: -list")
	doneFlag := flag.Int("done", 0, "Mark a task complete by ID: -done 1")
	delFlag := flag.Int("del", 0, "Delete a task by ID: -del 1")
	fileFlag := flag.String("file", "tasks.json", "Custom task file location: -file my_tasks.json")

	// Custom usage message
	flag.Usage = func() {
		fmt.Println("📋 CLI Task Tracker")
		fmt.Println("\nUsage:")
		fmt.Println("  go run main.go [flags]")
		fmt.Println("\nAvailable Flags:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  go run main.go -add \"Finish Go project\"")
		fmt.Println("  go run main.go -list")
		fmt.Println("  go run main.go -done 1")
		fmt.Println("  go run main.go -del 1")
	}

	flag.Parse()

	// If no flags were provided, show usage help
	if flag.NFlag() == 0 {
		flag.Usage()
		return
	}

	// Load existing tasks from disk
	tasks, err := loadTasks(*fileFlag)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	needsSave := false

	// Handle operations
	if *addFlag != "" {
		addTask(&tasks, *addFlag)
		needsSave = true
	}

	if *doneFlag > 0 {
		if completeTask(tasks, *doneFlag) {
			needsSave = true
		}
	}

	if *delFlag > 0 {
		if deleteTask(&tasks, *delFlag) {
			needsSave = true
		}
	}

	// Persist changes if any state was mutated
	if needsSave {
		if err := saveTasks(*fileFlag, tasks); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
	}

	// Always display the updated list if requested
	if *listFlag {
		listTasks(tasks)
	}
}
