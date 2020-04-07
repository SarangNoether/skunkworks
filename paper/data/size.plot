set term png enhanced lw 2 font 'Helvetica 20'
set output 'size.png'
set xlabel 'Anonymity set size'
set ylabel 'Total size (GB)'
set xrange [16:1024]
set logscale x 2
set format x '2^{%L}'
set yrange [0:12]
set key bottom
plot 'size.data' u 1:3 w lp ps 2 t 'RingCT 3.0', 'size.data' u 1:2 w lp ps 2 t 'RingCT 3.0 (new)', 'size.data' u 1:5 w lp ps 2 t 'Triptych', 'size.data' u 1:4 w lp ps 2 t 'Arcturus'
