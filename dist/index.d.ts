export declare class SafeToken<TimeWindow extends Record<string, number> = {
    access: number;
}> {
    private timeWindow;
    private secret;
    constructor(init: {
        timeWindows?: TimeWindow;
        secret: string;
    });
    create(data?: Record<string, string | number | boolean>): Promise<string>;
    verify(token: string, timeWindowKey?: keyof TimeWindow): Promise<Record<string, string | number | boolean>>;
    decode(token: string): any;
}
