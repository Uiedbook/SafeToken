export declare class SafeToken<TimeWindow extends Record<string, number> = {
    access: number;
}> {
    private timeWindow;
    private secret;
    constructor(init: {
        timeWindows?: TimeWindow;
        secret: string;
    });
    create(data?: Record<string, string | number | boolean>): string;
    verify(token: string, timeWindowKey?: keyof TimeWindow): any;
    decode(token: string): any;
}
