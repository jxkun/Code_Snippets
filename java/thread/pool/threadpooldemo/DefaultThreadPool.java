package api.thread.pool;

import javafx.concurrent.Worker;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 自定义线程池
 * @param <Job>
 */
public class DefaultThreadPool<Job extends Runnable> implements ThreadPool<Job> {
    private static final int MAX_WORKER_NUMBERS = 10;
    private static final int DEFAULT_WORKER_NUMBERS = 5;
    private static final int MIN_WORKER_NUMBERS = 1;
    // 工作列表， 向里面插入工作
    private final LinkedList<Job> jobs = new LinkedList<Job>();
    // 工作者列表
    private final List<Worker> workers = Collections.synchronizedList(new ArrayList<Worker>());
    // 工作线程数量
    private int workerNum = DEFAULT_WORKER_NUMBERS;
    // 工作线程编号生成
    private AtomicLong threadNum = new AtomicLong();

    public DefaultThreadPool(){
        initializeWorker(DEFAULT_WORKER_NUMBERS);
    }

    public DefaultThreadPool(int num){
        workerNum = num > MAX_WORKER_NUMBERS ? MAX_WORKER_NUMBERS : num < MIN_WORKER_NUMBERS ? MIN_WORKER_NUMBERS : num;
        initializeWorker(workerNum);
    }

    /**
     * 将Job添加到jobs队列，等待执行
     * @param job
     */
    @Override
    public void execute(Job job) {
        if(job != null){
            synchronized (jobs){
                jobs.addLast(job);
                jobs.notify();
            }
        }
    }

    /**
     * 关闭所有的worker
     */
    @Override
    public void shutdown() {
        for(Worker worker : workers){
            worker.shutdown();
        }
    }

    /**
     * 添加num个worker
     * @param num
     */
    @Override
    public void addWorkers(int num) {
        synchronized (jobs){
            if(num + this.workerNum > MAX_WORKER_NUMBERS){
                num = MAX_WORKER_NUMBERS - this.workerNum;
            }
            initializeWorker(num);
            this.workerNum += num;
        }
    }

    /**
     * 移除num个worker
     * @param num
     */
    @Override
    public void removeWorker(int num) {
        synchronized (jobs){
            if(num >= this.workerNum){
                throw new IllegalArgumentException("beyond workNum");
            }
            // 按照给定的数量停止Worker
            int count = 0;
            while(count < num){
                Worker worker = workers.get(count);
                if(workers.remove(worker)){
                    worker.shutdown();
                    count++;
                }
            }
            this.workerNum -= count;
        }
    }

    @Override
    public int getJobSize() {
        return jobs.size();
    }

    /**
     * 初始化工作线程
     * @param num
     */
    private void initializeWorker(int num){
        for(int i = 0; i < num; i++){
            Worker worker = new Worker();
            workers.add(worker);
            Thread thread = new Thread(worker, "ThreadPool-Worker-" + threadNum.incrementAndGet());
            thread.start();
        }
    }

    class Worker implements Runnable{
        // 是否工作
        private volatile boolean running = true;
        @Override
        public void run() {
            while(running){
                Job job = null;
                synchronized (jobs){
                    // 如果工作列表为空, wait
                    while(jobs.isEmpty()){
                        try {
                            jobs.wait();
                        } catch (InterruptedException e) {
                            // 感知外部对WorkerThread的中断操作, 返回
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                    // 取出一个Job
                    job = jobs.removeFirst();
                }
                if(job != null){
                    try{
                        job.run();
                    }catch (Exception e){
                        //System.out.println("");
                    }
                }
            }

        }
        // 不工作
        public void shutdown(){
            running = false;
        }
    }
}
