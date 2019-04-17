public class SimpleConsumer {
    //set get
    private static String BOOTSTRAP_SERVER="kafka.domain.com:9092";
    private static String TOPIC_NAME="topic";
    private static String GROUP_ID="group_id";

    public static void main(String[] args) throws Exception{
        StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        env.enableCheckpointing(3000);


        //set EventTime,the default is ProcessingTime
        env.setStreamTimeCharacteristic(TimeCharacteristic.EventTime);

        //get
        Properties sourceKafkaProperties = new Properties();
        sourceKafkaProperties.setProperty("bootstrap.servers",BOOTSTRAP_SERVER);
        sourceKafkaProperties.setProperty("group.id",GROUP_ID);

        //compress data
        sourceKafkaProperties.put("compression.type", "gzip");
        String jaasTemplate = "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"username\" password=\"password\";";
        sourceKafkaProperties.put("security.protocol", "SASL_PLAINTEXT");
        sourceKafkaProperties.put("sasl.mechanism", "PLAIN");
        sourceKafkaProperties.put("sasl.jaas.config", jaasTemplate);


        FlinkKafkaConsumer010<String> consumer010 = new FlinkKafkaConsumer010(TOPIC_NAME,new SimpleStringSchema(),sourceKafkaProperties);



        //解析数据
        DataStream<T> dataStream=env
        //DataStream<Long> dataStream=env
                .addSource(consumer010)
                .flatMap(new myFunction());

        //抽取timestamp设置watermark
        DataStream<T> waterMarkStream = dataStream.assignTimestampsAndWatermarks(new AssignerWithPeriodicWatermarks<T>() {

            Long currentMaxTimestamp = 0L;
            //允许最大乱序时间:10s
            final Long maxOutofOrderness = 10000L;

            @Nullable
            @Override
            public Watermark getCurrentWatermark() {
                return new Watermark(currentMaxTimestamp-maxOutofOrderness);
            }

            @Override
            public long extractTimestamp(T element, long previousElementTimestamp) {
                long timestamp = element.f0;
                currentMaxTimestamp = Math.max(timestamp,currentMaxTimestamp);

                return timestamp;
            }
        });


        
        DataStream<T> windowDatta = waterMarkStream
                .timeWindowAll(Time.minutes(1))
                .apply(new AllWindowFunction<T>, T, TimeWindow>() {
                    @Override
                    public void apply(TimeWindow window, Iterable<T> values, Collector<T> out) throws Exception {
			     T l;
                        out.collect(l);
                    }
                });

        windowDatta.print();

        env.execute("kafka start");
    }
}
