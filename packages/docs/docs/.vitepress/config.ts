
import { defineConfig } from "vitepress";

export default defineConfig({
    title: "Safe",
    description:
        "Secure cryptographic library for BIP-39, key derivation, encryption, and digital signatures.",

    cleanUrls: true,

    themeConfig: {
        nav: [
            { text: "Guide", link: "/getting-started" },
            { text: "API Reference", link: "/api" },
        ],

        sidebar: [
            {
                text: "Introduction",
                items: [
                    { text: "Overview", link: "/" },
                    {
                        text: "Getting Started",
                        link: "/getting-started",
                    },
                ],
            },
            {
                text: "Reference",
                items: [
                    { text: "API", link: "/api" },
                ],
            },
        ],

        socialLinks: [
            {
                icon: "github",
                link: "https://github.com/jasakode/safe",
            },
        ],

        search: {
            provider: "local",
        },
    },
});