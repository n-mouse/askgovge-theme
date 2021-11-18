# -*- encoding : utf-8 -*-
# Add a callback - to be executed before each request in development,
# and at startup in production - to patch existing app classes.
# Doing so in init/environment.rb wouldn't work in development, since
# classes are reloaded, but initialization is not run each time.
# See http://stackoverflow.com/questions/7072758/plugin-not-reloading-in-development-mode
#
Rails.configuration.to_prepare do

  PublicBodyController.class_eval do
    def list
      long_cache

      @tag = params[:tag] || 'all'
      @locale = AlaveteliLocalization.locale
      
      if @locale == "ka"
        @tag = @tag if @tag.scan(/./mu).size == 1
      else
        @tag = @tag.upcase if @tag.scan(/./mu).size == 1
      end

      @country_code = AlaveteliConfiguration.iso_country_code
      

      AlaveteliLocalization.with_locale(@locale) do
        @public_bodies = PublicBody.visible.
                                  with_tag(@tag).
                                  with_query(params[:public_body_query], @tag).
                                  paginate(page: params[:page], per_page: 100)

        @description =
          if @tag == 'all'
            n_('Found {{count}} public authority',
               'Found {{count}} public authorities',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries)
          elsif @tag.size == 1
            n_('Found {{count}} public authority beginning with ' \
               '‘{{first_letter}}’',
               'Found {{count}} public authorities beginning with ' \
               '‘{{first_letter}}’',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries,
               :first_letter => @tag)
          else
            category_name = PublicBodyCategory.get.by_tag[@tag]
            if category_name.nil?
              n_('Found {{count}} public authority matching the tag ' \
               '‘{{tag_name}}’',
               'Found {{count}} public authorities matching the tag ' \
               '‘{{tag_name}}’',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries,
               :tag_name => @tag)
            else
              n_('Found {{count}} public authority in the category ' \
               '‘{{category_name}}’',
               'Found {{count}} public authorities in the category ' \
               '‘{{category_name}}’',
               @public_bodies.total_entries,
               :count => @public_bodies.total_entries,
               :category_name => category_name)
            end
          end

        respond_to do |format|
          format.html { render :template => 'public_body/list' }
        end
      end
    end

  end
  # Example adding an instance variable to the frontpage controller
  # GeneralController.class_eval do
  #   def mycontroller
  #     @say_something = "Greetings friend"
  #   end
  # end
  # Example adding a new action to an existing controller
  # HelpController.class_eval do
  #   def help_out
  #   end
  # end
end
