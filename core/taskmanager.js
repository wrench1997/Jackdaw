


class taskmanager {
    constructor() {
        this.tasks = []; // an array to keep track of all the tasks
    }
    //Add once with the same tashid
    addTask(taskid, urlslength, call) {
        const existingTask = this.tasks.find(t => t.taskid === taskid);
        if (!existingTask) {
            this.tasks.push({ taskid, urlslength, processes: {}, call });// add the new task to the array
        }
    }
    addProcess(taskid, pid) {
        const task = this.tasks.find(t => t.taskid === taskid); // find the task with the given taskid
        if (task) {
            task.processes[pid] = true; // add the process to the task's list of processes
        }
    }
    processCompleted(pid) {
        const task = this.tasks.find(t => t.processes[pid]);
        if (task && task.processes[pid]) {
            delete task.processes[pid];
            task.urlslength--;
            console.log(`剩余目标数 ${task.urlslength}`)
        }
    }

    getTaskId(pid) {
        const taskWithPid = this.tasks.find(t => t.processes[pid]);
        return taskWithPid ? taskWithPid.taskid : null;
    }

    isTaskEnd(taskid) {
        const task = this.tasks.find(t => t.taskid === taskid);
        if (task && !task.urlslength) { // if the task exists and its urlslength value is 0
            task.call.end();
            return true; // return true to indicate that the task is completed and removed
        }
        return false; // return false if the task is not completed or not found
    }
    removeTask(taskid) {
        const index = this.tasks.findIndex(t => t.taskid === taskid); // find the index of the task with the given taskid
        if (index >= 0) { // if the task is found
            this.tasks.splice(index, 1); // remove the task from the array
            return true; // return true to indicate that the task is removed
        }
        return false; // return false if the task is not found
    }
    clearTasks() {
        this.tasks = [];
    }
}


module.exports = { taskmanager };