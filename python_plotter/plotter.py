import matplotlib.pyplot as plt
from os import walk, path, getcwd

def array_ctxt_tests_plot(op, legend):

    def __plot_test(file_name):

        fin = open(file_name, "r")
        tests = [[rnd for rnd in test.split('\n')[1:-2]] for test in fin.read().split("TEST")[1:]]

        len_time_avg = {} # {length: total time}, at the end, plot (length, time / number of tests)

        tcnt = 0

        for test in tests:

            if len(test) == 0:
                continue

            while '' in test:
                test.remove('')

            tcnt += 1

            for line in test:

                ws = line.split()
              
                if op != ws[0]:
                    continue

                time = float(ws[3])
                length = int(ws[10], 10)

                if length in len_time_avg.keys():
                    len_time_avg[length] += time
                else:
                    len_time_avg.update({length: time})

        for length in len_time_avg.keys():
            len_time_avg[length] /= tcnt

        to_plot_x = []
        to_plot_y = []

        for length, time in len_time_avg.items():

            to_plot_x.append(length)
            to_plot_y.append(time)

        plt.plot(to_plot_x, to_plot_y)

    files = []
    for (_, _, filenames) in walk(path.abspath(getcwd())):
        files.extend(filenames)
        break

    plt_legend = []

    for file in files:
        if "arrtest" in file:

            __plot_test(file)
            plt_legend.append(file)

    plt.xlabel('ciphertext length in default len chunks (n = 1247, s=16)')
    plt.ylabel('addition average time in miliseconds')
    if legend is True:
        plt.legend(plt_legend)
    plt.show()

def average_tests_plot(dectime, legend):

    def __plot_test(file_name):

        fin = open(file_name, "r")
        tests = [[rnd for rnd in test.split('\n')] for test in fin.read().split("TEST")]

        metadata = tests[0][0].split(',')

        ROUNDS_PER_TEST = int(metadata[0].split()[0], 10)
        ROUNDS_PER_THREAD = int(metadata[1].split()[0], 10)
        CS_CNT = int(metadata[2].split()[0], 10)
        EPOCH_CNT = int(metadata[3].split()[0], 10)
        DEL_FACTOR = int(metadata[4].split()[0], 10)

        rounds_per_epoch = ROUNDS_PER_TEST // EPOCH_CNT

        to_plot_x = [f"(0, {CS_CNT})"]
        plt.xlabel(f'(step, remaining ctxt count)\n{rounds_per_epoch} operations (+, *, perm) per step        n = 1247, s = 16')

        current_cs_cnt = CS_CNT
        for e in range(1, EPOCH_CNT):
            
            if DEL_FACTOR > 0:
                current_cs_cnt -= current_cs_cnt // DEL_FACTOR

            to_plot_x.append(f"({e}, {current_cs_cnt})")

        tests = tests[1:]

        to_plot_y = [0 for _ in range(EPOCH_CNT)]
        to_plot_y_dec = [0 for _ in range(EPOCH_CNT)]

        tcnt = 0

        for test in tests:

            if 'DONE' in test[0]:
                continue

            if len(test) == 0:
                continue

            tcnt += 1
            
            test = test[2:]

            while '' in test:
                test.remove('')

            for e in range(EPOCH_CNT):

                e_stats = test[e * 2 + 1].split()

                to_plot_y[e] += float(e_stats[3])
                to_plot_y_dec[e] += float(e_stats[6])

        to_plot_y = [val / tcnt for val in to_plot_y]
        to_plot_y_dec = [val / tcnt for val in to_plot_y_dec]

        plt.plot(to_plot_x, to_plot_y)
        if dectime is True:
            plt.plot(to_plot_x, to_plot_y_dec)

    files = []
    for (_, _, filenames) in walk(path.abspath(getcwd())):
        files.extend(filenames)
        break

    plt_legend = []

    for file in files:
        if "averagetest" in file:
            
            try:
                __plot_test(file)

                plt_legend.append(file)
                if dectime is True:
                    plt_legend.append(file + " (decryption)")

            except Exception as e:
                print(f"ERROR while trying to plot file {file}: {e.args}")

    plt.ylabel('average time in miliseconds')
    if legend is True:
        plt.legend(plt_legend)
    plt.show()

#array_ctxt_tests_plot("Addition", legend=True)
#array_ctxt_tests_plot("Multiplication", legend=True)

average_tests_plot(dectime=True, legend=True)