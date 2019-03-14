#!/usr/bin/env ruby -v

require 'rubygems'
require 'bundler/setup'

require 'rest-client'
require 'json'
require 'fileutils'
require 'logger'
require 'csv'

# Main logic of the challenge
class Neo

    THE_ONE = "https://challenge.distribusion.com/the_one"
    SOURCES = %w(sentinels sniffers loopholes)
    ROUTES = THE_ONE + "/routes"
    DATA_DIR = "data"

    def main
        @logger = Logger.new STDOUT
        @logger.level = :info
        #RestClient.log = @logger
        get_pill
        process_sources
    end

private

    def logger
        @logger
    end

    def get_pill
        the_one = get_json THE_ONE
        red_pill = the_one["pills"]["red"]
        @passphrase = red_pill["passphrase"]
        logger.info "got a pill"
    end

    def get_json(url, params = {})
        response = RestClient.get url, params: params, accept: :json
        JSON.parse response.body
    end

    def process_sources
        SOURCES.each do |source|
            logger.info "**** processing source #{source}"
            download_source_data source unless ARGV.include? "--skipdl" 
            data_dir = source_data_dir source
            import_source_data source, data_dir
        end
    end

    def source_data_dir(source)
        "#{DATA_DIR}/#{source}"
    end

    def download_source_data(source)
        params = {  source: source, passphrase: @passphrase }
        response = RestClient.get ROUTES, params: params
        logger.info "got source #{source}: #{response.headers.inspect}"
        raise "unsupported source type" unless response.headers[:content_type] == "application/zip"
        FileUtils.mkdir_p DATA_DIR
        fname = "#{DATA_DIR}/#{source}.zip"
        File.write fname, response.body
        system "unzip -u #{fname} -d #{DATA_DIR}"
        data_dir = source_data_dir source
        raise "unzipped data missing" unless Dir.exist? data_dir
        logger.info "unzipped to #{data_dir}"
        data_dir
    end

    def import_source_data(source, data_dir)
        klass = Object.const_get source.capitalize
        analyzer = klass.new logger
        analyzer.load_data data_dir
        post_data source, analyzer.get_routes
    end

    def post_data(source, routes)
        logger.info "*** importing source #{source}"
        routes.each do |route|
            payload = route.to_h
            payload["source"] = source
            payload["passphrase"] = @passphrase
            # convert time to UTC strings
            payload[:start_time] = payload[:start_time].new_offset(0).strftime("%FT%T") if payload[:start_time]
            payload[:end_time] = payload[:end_time].new_offset(0).strftime("%FT%T") if payload[:end_time]
            logger.debug "POST #{ROUTES} #{payload.inspect}"
            response = RestClient.post ROUTES, payload
            logger.info "POST response #{response.code}"
        end
    end

end

# Route definition as required by import API
Route = Struct.new :start_node, :end_node, :start_time,:end_time

# Base for source analyzers
# Stores routes for simplicity
class BaseRouteAnalyzer

    def initialize(logger)
        @logger = logger
        @routes = []
    end

    def get_routes
        @routes
    end

protected

    def logger
        @logger
    end

    def add_route(route)
        logger.info "adding route #{route}"
        @routes << route
    end

    # iterate over each record(as Hash) contained in csv,
    # where first row must contain keys for the record
    def each_csv_record(filename)
        sheet = CSV.read(filename,liberal_parsing: true, col_sep: ", ")
        keys = sheet[0]
        1.upto(sheet.size-1).each do |row_index|
            row = sheet[row_index]
            logger.debug "#{row.inspect}"
            record = Hash.new
            0.upto(keys.size-1) do |column|
                record[keys[column]] = row[column]
            end
            logger.debug "record #{record.inspect}"
            yield record
        end
    end

end

class Sentinels < BaseRouteAnalyzer

    def load_data(data_dir)
        # remember all routes in nested Hash, first by route_id then by node index
        routes_by_id = Hash.new { |hash, key| hash[key] = Hash.new }
        each_csv_record "#{data_dir}/routes.csv" do |record|
            route_records = routes_by_id[record["route_id"]]
            logger.info "route_records id #{record["route_id"]}: #{route_records.inspect}"
                index = record["index"].to_i
                previous_node = route_records[index-1]
                if previous_node
                    # have records for start and end node, so can create full route 
                    add_route_for_nodes previous_node, record
                end
            route_records[index] = record
            logger.info "added record #{index}"
        end
    end

    def add_route_for_nodes(start_node, end_node)
        route = Route.new 
        route.start_node = start_node["node"]
        route.start_time = DateTime.parse(start_node["time"])
        route.end_node = end_node["node"]
        route.end_time = DateTime.parse end_node["time"]
        add_route route
    end


end

class Sniffers < BaseRouteAnalyzer

    def load_data(data_dir)
        # remember all routes in nested Hash, first by route_id then by node index
        routes_by_id = Hash.new 
        each_csv_record "#{data_dir}/routes.csv" do |record|
            routes_by_id[record["route_id"]] = record
        end

        node_times_by_id = Hash.new 
        each_csv_record "#{data_dir}/node_times.csv" do |record|
            node_times_by_id[record["node_time_id"]] = record
        end
        
        each_csv_record "#{data_dir}/sequences.csv" do |record|
            route = routes_by_id[record["route_id"]] 
            node_times = node_times_by_id[record["node_time_id"]]
            if route && node_times
                add_route_with_times(route, node_times)
            else
                logger.error "Missing data for route #{record["route_id"]} node_time #{record["node_time_id"]}"
            end
        end
    end

    def add_route_with_times(sniffer_route, node_times)
        route = Route.new 
        route.start_node = node_times["start_node"]
        route.end_node = node_times["end_node"]
        route.start_time = DateTime.iso8601 sniffer_route["time"] + "+" + sniffer_route["time_zone"][4..8]
        time =  route.start_time.to_time + (node_times["duration_in_milliseconds"].to_i / 1000.0)
        route.end_time = time.to_datetime
        add_route route
    end

end

class Loopholes < BaseRouteAnalyzer

    def load_data(data_dir)

        node_pairs = JSON.parse( File.read("#{data_dir}/node_pairs.json") )["node_pairs"]
        routes = JSON.parse( File.read("#{data_dir}/routes.json") )["routes"]

        logger.debug node_pairs.inspect
        logger.debug routes.inspect

        routes.each do |route|
            logger.debug route.inspect
            node_pair = node_pairs.find { |x| x["id"] == route["node_pair_id"] }
            if node_pair
                add_route_for route, node_pair
            else
                logger.error "Missing node pair #{route["node_pair_id"]}"
            end
        end
    end

    def add_route_for(loophole_route, node_pair)
        route = Route.new 
        route.start_node = node_pair["start_node"]
        route.end_node = node_pair["end_node"]
        route.start_time = DateTime.iso8601 loophole_route["start_time"]
        route.end_time = DateTime.iso8601 loophole_route["end_time"]
        add_route route     
    end

end

Neo.new.main
