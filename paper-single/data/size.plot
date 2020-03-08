set term png enhanced lw 2 font 'Helvetica 20'
set output 'triptych.png'
set xlabel 'N'
set ylabel 'Size (kB)'
set xrange [2:8192]
set logscale x 2
set format x '2^{%L}'
set yrange [0.1:1000]
set logscale y 10
set format y '10^{%L}'
set key top left
plot 'triptych.data' u 1:2 w lp ps 2 t 'CLSAG', 'triptych.data' u 1:3 w lp ps 2 t 'RingCT 3.0', 'triptych.data' u 1:4 w lp ps 2 t 'Triptych'
