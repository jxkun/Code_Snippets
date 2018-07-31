package jdk.thread.pool.demo;

public interface ThreadPool<Job extends Runnable> {
    /**
     * 执行一个Job
     * @param job
     */
    void execute(Job job);

    /**
     * 关闭线程池
     */
    void shutdown();

    /**
     * 添加工作者线程数量
     * @param num
     */
    void addWorkers(int num);

    /**
     * 减少工作者数量
     * @param num
     */
    void removeWorker(int num);

    /**
     * 获取正在等待执行的任务数量
     * @return
     */
    int getJobSize();
}
