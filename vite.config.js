import sharp from 'vite-plugin-sharp';
import vitePluginD2 from 'vite-plugin-d2';

export default {
    build: {
        // Output directory.
        outDir: 'public/static',

        // Avoid copying files that are not assets.
        copyPublicDir: false,

        // Entry points.
        rollupOptions: {
            input: {
                app: './assets/js/app.js',          // Main JS.
                styles: './assets/css/app.css',     // Main CSS.
                images: './assets/js/images.js'     // Images.
            },
            output: {
                // Output file names.
                entryFileNames: 'js/[name].min.js',
                assetFileNames: (assetInfo) => {
                    if (assetInfo.name.endsWith('.css')) {
                        return 'css/[name].min.css';
                    }

                    // We use originalFileNames to maintain the structure.
                    if (assetInfo.originalFileNames && assetInfo.originalFileNames[0]) {
                        // We remove 'assets/' from the beginning and keep the rest of the path.
                        return assetInfo.originalFileNames[0].replace('assets/', '');
                    }

                    return assetInfo.name;
                }
            }
        }
    },
    plugins: [
        vitePluginD2({
            outputDir: 'assets/img',
            layout: 'elk'
        }),
        sharp({
            // General settings.
            force: true, // Process all images.

            // Configuration by image type.
            png: {
                quality: 85,
                compressionLevel: 9 // 0-9, higher = more compression.
            },
            jpeg: {
                quality: 85,
                progressive: true
            },

            // Optional: Resize all large images.
            resize: {
                width: 2000,  // Maximum width.
                height: 2000, // Maximum high.
                fit: 'inside' // Maintains proportion.
            }
        })
    ],
}
