


declare global {
    var Go: {
        new(): {
            argv: string[];
            env: Record<string, string>;
            importObject: WebAssembly.Imports;
            run(instance: WebAssembly.Instance): Promise<void>;
        };
    };

    var __SAFE: SafeAPI | undefined;
}

export { };
