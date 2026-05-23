module.exports = function( grunt ) {
    grunt.initConfig( {
        pkg: grunt.file.readJSON( 'package.json' ),

        bower: {
            install: {
                options: {
                    copy: true
                }
            }
        },

        clean: {
            dist: {
                options: { force: true },
                build: [ 'bower_components', 'lib', '../src/main/webapp/lib' ]
            },
            nodeModules: ['./node_modules']
        },

        copy : {
            main : {
                files: [ { expand: true, cwd: 'lib/', src: [ '**/*', '!**/bootstrap-css-only/**' ], dest: '../src/main/webapp/lib' },
                    { expand: true, cwd: 'lib/bootstrap-css-only/', src: [ '*.css' ], dest: '../src/main/webapp/lib/bootstrap-css-only/css/' },
                    { expand: true, cwd: 'lib/bootstrap-css-only/', src: [ 'glyphicons*' ], dest: '../src/main/webapp/lib/bootstrap-css-only/fonts/' } ]
            }
        }
    });

    grunt.loadNpmTasks( 'grunt-bower-task' );
    grunt.loadNpmTasks( 'grunt-contrib-clean' );
    grunt.loadNpmTasks( 'grunt-contrib-copy' );

    grunt.registerTask( 'resolve', [ 'clean:dist', 'bower:install', 'copy' ] );
    grunt.registerTask( 'remove-node-modules', [ 'clean:nodeModules'] );
};
